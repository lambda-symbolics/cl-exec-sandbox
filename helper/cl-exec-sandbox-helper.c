#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/if.h>
#include <linux/seccomp.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#define MAX_ROUTES 16
#define MAX_PROXY_VALUE 2048
#define MAX_ROUTE_SPEC 32768

static const char *proxy_keys[] = {
  "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "FTP_PROXY",
  "YARN_HTTP_PROXY", "YARN_HTTPS_PROXY", "NPM_CONFIG_HTTP_PROXY",
  "NPM_CONFIG_HTTPS_PROXY", "NPM_CONFIG_PROXY", "BUNDLE_HTTP_PROXY",
  "BUNDLE_HTTPS_PROXY", "PIP_PROXY", "DOCKER_HTTP_PROXY",
  "DOCKER_HTTPS_PROXY", "http_proxy", "https_proxy", "all_proxy",
  "ftp_proxy", "yarn_http_proxy", "yarn_https_proxy",
  "npm_config_http_proxy", "npm_config_https_proxy", "npm_config_proxy",
  "bundle_http_proxy", "bundle_https_proxy", "pip_proxy",
  "docker_http_proxy", "docker_https_proxy", NULL
};

struct proxy_route {
  char key[64];
  char value[MAX_PROXY_VALUE];
  char host[INET6_ADDRSTRLEN];
  uint16_t port;
  char socket_path[sizeof(((struct sockaddr_un *)0)->sun_path)];
};

static void fail(const char *message)
{
  fprintf(stderr, "cl-exec-sandbox-helper: %s: %s\n", message,
          strerror(errno));
  exit(125);
}

static void fail_message(const char *message)
{
  fprintf(stderr, "cl-exec-sandbox-helper: %s\n", message);
  exit(125);
}

static void set_parent_death_signal(void)
{
  if (prctl(PR_SET_PDEATHSIG, SIGKILL) != 0)
    fail("could not set parent-death signal");
  if (getppid() == 1)
    _exit(125);
}

static int write_all(int fd, const void *buffer, size_t length)
{
  const char *cursor = buffer;
  while (length > 0) {
    ssize_t written = write(fd, cursor, length);
    if (written < 0) {
      if (errno == EINTR)
        continue;
      return -1;
    }
    cursor += written;
    length -= (size_t)written;
  }
  return 0;
}

static int read_all(int fd, void *buffer, size_t length)
{
  char *cursor = buffer;
  while (length > 0) {
    ssize_t count = read(fd, cursor, length);
    if (count == 0) {
      errno = EPIPE;
      return -1;
    }
    if (count < 0) {
      if (errno == EINTR)
        continue;
      return -1;
    }
    cursor += count;
    length -= (size_t)count;
  }
  return 0;
}

static void proxy_copy_loop(int left, int right)
{
  struct pollfd descriptors[2] = {
    { .fd = left, .events = POLLIN },
    { .fd = right, .events = POLLIN }
  };
  char buffer[16384];

  for (;;) {
    int ready = poll(descriptors, 2, -1);
    if (ready < 0) {
      if (errno == EINTR)
        continue;
      break;
    }
    for (size_t index = 0; index < 2; ++index) {
      if (!(descriptors[index].revents & (POLLIN | POLLHUP | POLLERR)))
        continue;
      int source = descriptors[index].fd;
      int destination = descriptors[1 - index].fd;
      ssize_t count = read(source, buffer, sizeof(buffer));
      if (count <= 0) {
        shutdown(destination, SHUT_WR);
        descriptors[index].fd = -1;
        descriptors[index].events = 0;
        if (descriptors[1 - index].fd < 0)
          return;
        continue;
      }
      if (write_all(destination, buffer, (size_t)count) != 0)
        return;
    }
  }
}

static int parse_port(const char *text, uint16_t *port)
{
  char *end = NULL;
  errno = 0;
  unsigned long value = strtoul(text, &end, 10);
  if (errno != 0 || end == text || *end != '\0' || value == 0 || value > 65535)
    return -1;
  *port = (uint16_t)value;
  return 0;
}

static int parse_proxy_endpoint(const char *value, char *host, size_t host_size,
                                uint16_t *port)
{
  const char *scheme_end = strstr(value, "://");
  const char *authority = scheme_end ? scheme_end + 3 : value;
  const char *authority_end = authority + strcspn(authority, "/?#");
  const char *at = NULL;
  for (const char *cursor = authority; cursor < authority_end; ++cursor)
    if (*cursor == '@')
      at = cursor;
  if (at)
    authority = at + 1;

  const char *port_text = NULL;
  size_t host_length = 0;
  char port_buffer[16];
  if (authority < authority_end && *authority == '[') {
    const char *close = memchr(authority, ']', (size_t)(authority_end - authority));
    if (!close)
      return -1;
    host_length = (size_t)(close - authority - 1);
    if (close + 1 < authority_end) {
      if (close[1] != ':')
        return -1;
      size_t length = (size_t)(authority_end - close - 2);
      if (length == 0 || length >= sizeof(port_buffer))
        return -1;
      memcpy(port_buffer, close + 2, length);
      port_buffer[length] = '\0';
      port_text = port_buffer;
    }
    authority++;
  } else {
    const char *colon = NULL;
    for (const char *cursor = authority; cursor < authority_end; ++cursor)
      if (*cursor == ':')
        colon = cursor;
    if (colon) {
      host_length = (size_t)(colon - authority);
      size_t length = (size_t)(authority_end - colon - 1);
      if (length == 0 || length >= sizeof(port_buffer))
        return -1;
      memcpy(port_buffer, colon + 1, length);
      port_buffer[length] = '\0';
      port_text = port_buffer;
    } else {
      host_length = (size_t)(authority_end - authority);
    }
  }

  if (host_length == 0 || host_length >= host_size)
    return -1;
  memcpy(host, authority, host_length);
  host[host_length] = '\0';
  if (strcasecmp(host, "localhost") == 0)
    strcpy(host, "127.0.0.1");
  if (strcmp(host, "127.0.0.1") != 0 && strcmp(host, "::1") != 0)
    return -1;

  if (port_text)
    return parse_port(port_text, port);
  if (scheme_end && (size_t)(scheme_end - value) == 5 &&
      strncasecmp(value, "https", 5) == 0)
    *port = 443;
  else
    *port = 80;
  return 0;
}

static int connect_tcp(const char *host, uint16_t port)
{
  int family = strchr(host, ':') ? AF_INET6 : AF_INET;
  int descriptor = socket(family, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (descriptor < 0)
    return -1;
  if (family == AF_INET) {
    struct sockaddr_in address = { .sin_family = AF_INET,
                                   .sin_port = htons(port) };
    if (inet_pton(AF_INET, host, &address.sin_addr) != 1 ||
        connect(descriptor, (struct sockaddr *)&address, sizeof(address)) != 0) {
      close(descriptor);
      return -1;
    }
  } else {
    struct sockaddr_in6 address = { .sin6_family = AF_INET6,
                                    .sin6_port = htons(port) };
    if (inet_pton(AF_INET6, host, &address.sin6_addr) != 1 ||
        connect(descriptor, (struct sockaddr *)&address, sizeof(address)) != 0) {
      close(descriptor);
      return -1;
    }
  }
  return descriptor;
}

static int connect_unix(const char *path)
{
  int descriptor = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (descriptor < 0)
    return -1;
  struct sockaddr_un address = { .sun_family = AF_UNIX };
  if (strlen(path) >= sizeof(address.sun_path)) {
    close(descriptor);
    errno = ENAMETOOLONG;
    return -1;
  }
  strcpy(address.sun_path, path);
  if (connect(descriptor, (struct sockaddr *)&address, sizeof(address)) != 0) {
    close(descriptor);
    return -1;
  }
  return descriptor;
}

static void host_bridge(const struct proxy_route *route, int ready_fd)
{
  set_parent_death_signal();
  int listener = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (listener < 0)
    _exit(125);
  struct sockaddr_un address = { .sun_family = AF_UNIX };
  strcpy(address.sun_path, route->socket_path);
  unlink(route->socket_path);
  if (bind(listener, (struct sockaddr *)&address, sizeof(address)) != 0 ||
      listen(listener, 16) != 0)
    _exit(125);
  char ready = 1;
  if (write_all(ready_fd, &ready, 1) != 0)
    _exit(125);
  close(ready_fd);

  for (;;) {
    int client = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
    if (client < 0) {
      if (errno == EINTR)
        continue;
      _exit(125);
    }
    pid_t child = fork();
    if (child == 0) {
      set_parent_death_signal();
      close(listener);
      int target = connect_tcp(route->host, route->port);
      if (target >= 0)
        proxy_copy_loop(client, target);
      _exit(0);
    }
    close(client);
    while (waitpid(-1, NULL, WNOHANG) > 0)
      ;
  }
}

static void ensure_loopback_up(void)
{
  int descriptor = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (descriptor < 0)
    fail("could not open loopback control socket");
  struct ifreq request;
  memset(&request, 0, sizeof(request));
  strcpy(request.ifr_name, "lo");
  if (ioctl(descriptor, SIOCGIFFLAGS, &request) != 0) {
    close(descriptor);
    fail("could not read loopback flags");
  }
  /* Bubblewrap normally enables lo before dropping CAP_NET_ADMIN. */
  if (request.ifr_flags & IFF_UP) {
    close(descriptor);
    return;
  }
  request.ifr_flags |= IFF_UP;
  if (ioctl(descriptor, SIOCSIFFLAGS, &request) != 0) {
    close(descriptor);
    fail("could not enable loopback");
  }
  close(descriptor);
}

static int loopback_listener(uint16_t *port)
{
  int descriptor = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (descriptor < 0)
    return -1;
  int enabled = 1;
  setsockopt(descriptor, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled));
  struct sockaddr_in address = { .sin_family = AF_INET,
                                 .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
                                 .sin_port = 0 };
  if (bind(descriptor, (struct sockaddr *)&address, sizeof(address)) != 0 ||
      listen(descriptor, 16) != 0) {
    close(descriptor);
    return -1;
  }
  socklen_t length = sizeof(address);
  if (getsockname(descriptor, (struct sockaddr *)&address, &length) != 0) {
    close(descriptor);
    return -1;
  }
  *port = ntohs(address.sin_port);
  return descriptor;
}

static void local_bridge(const char *socket_path, int ready_fd)
{
  set_parent_death_signal();
  uint16_t port;
  int listener = loopback_listener(&port);
  if (listener < 0)
    _exit(125);
  uint16_t network_port = htons(port);
  if (write_all(ready_fd, &network_port, sizeof(network_port)) != 0)
    _exit(125);
  close(ready_fd);

  for (;;) {
    int client = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
    if (client < 0) {
      if (errno == EINTR)
        continue;
      _exit(125);
    }
    pid_t child = fork();
    if (child == 0) {
      set_parent_death_signal();
      close(listener);
      int target = connect_unix(socket_path);
      if (target >= 0)
        proxy_copy_loop(client, target);
      _exit(0);
    }
    close(client);
    while (waitpid(-1, NULL, WNOHANG) > 0)
      ;
  }
}

static int rewrite_proxy_value(const char *value, uint16_t port,
                               char *rewritten, size_t rewritten_size)
{
  const char *scheme_end = strstr(value, "://");
  const char *authority = scheme_end ? scheme_end + 3 : value;
  const char *authority_end = authority + strcspn(authority, "/?#");
  const char *host_start = authority;
  const char *at = NULL;
  for (const char *cursor = authority; cursor < authority_end; ++cursor)
    if (*cursor == '@')
      at = cursor;
  if (at)
    host_start = at + 1;
  int count = snprintf(rewritten, rewritten_size, "%.*s127.0.0.1:%u%s",
                       (int)(host_start - value), value, (unsigned)port,
                       authority_end);
  return count < 0 || (size_t)count >= rewritten_size ? -1 : 0;
}

static size_t parse_route_spec(char *spec, struct proxy_route *routes)
{
  size_t count = 0;
  char *record_save = NULL;
  for (char *record = strtok_r(spec, "\036", &record_save);
       record && count < MAX_ROUTES;
       record = strtok_r(NULL, "\036", &record_save)) {
    char *field_save = NULL;
    char *key = strtok_r(record, "\037", &field_save);
    char *value = strtok_r(NULL, "\037", &field_save);
    char *path = strtok_r(NULL, "\037", &field_save);
    if (!key || !value || !path)
      fail_message("malformed managed-proxy route specification");
    if (strlen(key) >= sizeof(routes[count].key) ||
        strlen(value) >= sizeof(routes[count].value) ||
        strlen(path) >= sizeof(routes[count].socket_path))
      fail_message("managed-proxy route is too long");
    strcpy(routes[count].key, key);
    strcpy(routes[count].value, value);
    strcpy(routes[count].socket_path, path);
    count++;
  }
  return count;
}

static void activate_local_proxy_routes(void)
{
  const char *raw_spec = getenv("CL_EXEC_SANDBOX_PROXY_ROUTES");
  if (!raw_spec || strlen(raw_spec) >= MAX_ROUTE_SPEC)
    fail_message("managed-proxy route specification is missing or too long");
  char *spec = strdup(raw_spec);
  if (!spec)
    fail("could not copy managed-proxy route specification");
  unsetenv("CL_EXEC_SANDBOX_PROXY_ROUTES");
  struct proxy_route routes[MAX_ROUTES];
  memset(routes, 0, sizeof(routes));
  size_t count = parse_route_spec(spec, routes);
  if (count == 0)
    fail_message("managed proxy mode requires at least one proxy route");
  ensure_loopback_up();

  for (size_t index = 0; index < count; ++index) {
    int ready[2];
    if (pipe2(ready, O_CLOEXEC) != 0)
      fail("could not create local-proxy readiness pipe");
    pid_t child = fork();
    if (child < 0)
      fail("could not start local proxy bridge");
    if (child == 0) {
      close(ready[0]);
      local_bridge(routes[index].socket_path, ready[1]);
      _exit(125);
    }
    close(ready[1]);
    uint16_t network_port;
    if (read_all(ready[0], &network_port, sizeof(network_port)) != 0)
      fail("local proxy bridge did not become ready");
    close(ready[0]);
    char rewritten[MAX_PROXY_VALUE];
    if (rewrite_proxy_value(routes[index].value, ntohs(network_port),
                            rewritten, sizeof(rewritten)) != 0)
      fail_message("could not rewrite proxy environment value");
    if (setenv(routes[index].key, rewritten, 1) != 0)
      fail("could not publish proxy environment value");
  }
  free(spec);
}

static void append_filter(struct sock_filter *filter, size_t *count,
                          struct sock_filter instruction)
{
  if (*count >= 128)
    fail_message("internal seccomp program is too large");
  filter[(*count)++] = instruction;
}

static void append_denied_syscall(struct sock_filter *filter, size_t *count,
                                  int syscall_number)
{
  append_filter(filter, count,
                (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                                             offsetof(struct seccomp_data, nr)));
  append_filter(filter, count,
                (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                             syscall_number, 0, 1));
  append_filter(filter, count,
                (struct sock_filter)BPF_STMT(BPF_RET | BPF_K,
                                             SECCOMP_RET_ERRNO | EPERM));
}

static void append_socket_family_filter(struct sock_filter *filter, size_t *count,
                                        int syscall_number, int first_family,
                                        int second_family)
{
  append_filter(filter, count,
                (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                                             offsetof(struct seccomp_data, nr)));
  unsigned char skip = second_family >= 0 ? 4 : 3;
  append_filter(filter, count,
                (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                             syscall_number, 0, skip));
  append_filter(filter, count,
                (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                                             offsetof(struct seccomp_data, args[0])));
  append_filter(filter, count,
                (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                             first_family,
                                             second_family >= 0 ? 2 : 1, 0));
  if (second_family >= 0)
    append_filter(filter, count,
                  (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                               second_family, 1, 0));
  append_filter(filter, count,
                (struct sock_filter)BPF_STMT(BPF_RET | BPF_K,
                                             SECCOMP_RET_ERRNO | EPERM));
}

static void install_seccomp(const char *mode)
{
  struct sock_filter filter[128];
  size_t count = 0;
  append_filter(filter, &count,
                (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                                             offsetof(struct seccomp_data, arch)));
  append_filter(filter, &count,
                (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                             AUDIT_ARCH_X86_64, 1, 0));
  append_filter(filter, &count,
                (struct sock_filter)BPF_STMT(BPF_RET | BPF_K,
                                             SECCOMP_RET_KILL_PROCESS));

  append_denied_syscall(filter, &count, SYS_ptrace);
  append_denied_syscall(filter, &count, SYS_process_vm_readv);
  append_denied_syscall(filter, &count, SYS_process_vm_writev);
#ifdef SYS_io_uring_setup
  append_denied_syscall(filter, &count, SYS_io_uring_setup);
  append_denied_syscall(filter, &count, SYS_io_uring_enter);
  append_denied_syscall(filter, &count, SYS_io_uring_register);
#endif

  if (strcmp(mode, "isolated") == 0) {
    int denied[] = { SYS_connect, SYS_accept, SYS_accept4, SYS_bind, SYS_listen,
                     SYS_getpeername, SYS_getsockname, SYS_shutdown, SYS_sendto,
                     SYS_sendmmsg, SYS_recvmmsg, SYS_getsockopt, SYS_setsockopt };
    for (size_t index = 0; index < sizeof(denied) / sizeof(denied[0]); ++index)
      append_denied_syscall(filter, &count, denied[index]);
    append_socket_family_filter(filter, &count, SYS_socket, AF_UNIX, -1);
    append_socket_family_filter(filter, &count, SYS_socketpair, AF_UNIX, -1);
  } else if (strcmp(mode, "proxy-only") == 0) {
    append_socket_family_filter(filter, &count, SYS_socket, AF_INET, AF_INET6);
    append_socket_family_filter(filter, &count, SYS_socketpair, AF_UNIX, -1);
  } else {
    fail_message("unknown seccomp network mode");
  }

  append_filter(filter, &count,
                (struct sock_filter)BPF_STMT(BPF_RET | BPF_K,
                                             SECCOMP_RET_ALLOW));
  struct sock_fprog program = { .len = (unsigned short)count, .filter = filter };
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
    fail("could not set no_new_privs");
  if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) != 0)
    fail("could not install seccomp filter");
}

static int inner_main(int argc, char **argv)
{
  if (argc < 5 || strcmp(argv[3], "--") != 0)
    fail_message("usage: helper inner MODE -- COMMAND [ARG ...]");
  const char *mode = argv[2];
  if (strcmp(mode, "proxy-only") == 0)
    activate_local_proxy_routes();
  if (strcmp(mode, "enabled") != 0)
    install_seccomp(mode);
  execvp(argv[4], &argv[4]);
  fail("could not execute sandboxed command");
  return 125;
}

static size_t collect_proxy_routes(struct proxy_route *routes,
                                   const char *socket_directory)
{
  size_t count = 0;
  for (const char **key = proxy_keys; *key && count < MAX_ROUTES; ++key) {
    const char *value = getenv(*key);
    if (!value || !*value)
      continue;
    if (strchr(value, '\036') || strchr(value, '\037'))
      fail_message("proxy environment value contains a reserved control byte");
    if (strlen(value) >= sizeof(routes[count].value))
      fail_message("proxy environment value is too long");
    if (parse_proxy_endpoint(value, routes[count].host,
                             sizeof(routes[count].host),
                             &routes[count].port) != 0)
      continue;
    strcpy(routes[count].key, *key);
    strcpy(routes[count].value, value);
    int length = snprintf(routes[count].socket_path,
                          sizeof(routes[count].socket_path), "%s/route-%zu.sock",
                          socket_directory, count);
    if (length < 0 || (size_t)length >= sizeof(routes[count].socket_path))
      fail_message("managed-proxy socket path is too long");
    count++;
  }
  return count;
}

static void stop_bridges(pid_t *bridges, size_t count)
{
  for (size_t index = 0; index < count; ++index)
    if (bridges[index] > 0)
      kill(bridges[index], SIGKILL);
  for (size_t index = 0; index < count; ++index)
    if (bridges[index] > 0)
      while (waitpid(bridges[index], NULL, 0) < 0 && errno == EINTR)
        ;
}

static int proxy_outer_main(int argc, char **argv)
{
  if (argc < 5 || strcmp(argv[2], "--") != 0)
    fail_message("usage: helper proxy-outer -- BWRAP [ARG ...]");
  char socket_template[] = "/tmp/cl-exec-sandbox-proxy-XXXXXX";
  char *socket_directory = mkdtemp(socket_template);
  if (!socket_directory)
    fail("could not create managed-proxy socket directory");
  chmod(socket_directory, 0700);

  struct proxy_route routes[MAX_ROUTES];
  memset(routes, 0, sizeof(routes));
  size_t route_count = collect_proxy_routes(routes, socket_directory);
  if (route_count == 0)
    fail_message("managed proxy mode requires a loopback proxy environment value");

  pid_t bridges[MAX_ROUTES];
  memset(bridges, 0, sizeof(bridges));
  for (size_t index = 0; index < route_count; ++index) {
    int ready[2];
    if (pipe2(ready, O_CLOEXEC) != 0)
      fail("could not create host-proxy readiness pipe");
    pid_t child = fork();
    if (child < 0)
      fail("could not start host proxy bridge");
    if (child == 0) {
      close(ready[0]);
      host_bridge(&routes[index], ready[1]);
      _exit(125);
    }
    bridges[index] = child;
    close(ready[1]);
    char ready_byte;
    if (read_all(ready[0], &ready_byte, 1) != 0)
      fail("host proxy bridge did not become ready");
    close(ready[0]);
  }

  char route_spec[MAX_ROUTE_SPEC];
  size_t used = 0;
  for (size_t index = 0; index < route_count; ++index) {
    int length = snprintf(route_spec + used, sizeof(route_spec) - used,
                          "%s\037%s\037%s%c", routes[index].key,
                          routes[index].value, routes[index].socket_path,
                          index + 1 == route_count ? '\0' : '\036');
    if (length < 0 || (size_t)length >= sizeof(route_spec) - used)
      fail_message("managed-proxy route specification is too long");
    used += (size_t)length;
  }
  if (setenv("CL_EXEC_SANDBOX_PROXY_ROUTES", route_spec, 1) != 0)
    fail("could not publish managed-proxy routes");

  int separator = -1;
  for (int index = 3; index < argc; ++index)
    if (strcmp(argv[index], "--") == 0) {
      separator = index;
      break;
    }
  if (separator < 0)
    fail_message("bubblewrap command has no command separator");
  char **command = calloc((size_t)argc + 7, sizeof(char *));
  if (!command)
    fail("could not allocate managed-proxy command");
  int output = 0;
  for (int index = 3; index < separator; ++index)
    command[output++] = argv[index];
  command[output++] = "--dir";
  command[output++] = "/tmp";
  command[output++] = "--ro-bind";
  command[output++] = socket_directory;
  command[output++] = socket_directory;
  for (int index = separator; index < argc; ++index)
    command[output++] = argv[index];
  command[output] = NULL;

  pid_t sandbox = fork();
  if (sandbox < 0)
    fail("could not start bubblewrap");
  if (sandbox == 0) {
    execvp(command[0], command);
    _exit(125);
  }
  int status;
  while (waitpid(sandbox, &status, 0) < 0)
    if (errno != EINTR)
      fail("could not wait for bubblewrap");
  stop_bridges(bridges, route_count);
  for (size_t index = 0; index < route_count; ++index)
    unlink(routes[index].socket_path);
  rmdir(socket_directory);
  free(command);
  if (WIFEXITED(status))
    return WEXITSTATUS(status);
  if (WIFSIGNALED(status))
    return 128 + WTERMSIG(status);
  return 125;
}

int main(int argc, char **argv)
{
  if (argc < 2)
    fail_message("an internal mode is required");
  if (strcmp(argv[1], "inner") == 0)
    return inner_main(argc, argv);
  if (strcmp(argv[1], "proxy-outer") == 0)
    return proxy_outer_main(argc, argv);
  fail_message("unknown internal mode");
  return 125;
}
