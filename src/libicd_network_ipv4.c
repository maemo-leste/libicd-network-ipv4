#include <osso-ic-dbus.h>
#include <icd/osso-ic-gconf.h>
#include <gconf/gconf-client.h>

#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>


#include <net/route.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#include "icd_dbus.h"
#include "icd_gconf.h"
#include "icd_log.h"
#include "network_api.h"

static gchar *_icd_gconf_get_iap_string(const char *iap_name, const char *key_name);
static gboolean _icd_gconf_get_iap_bool(const char *iap_name, const char *key_name, gboolean def);

struct _ipv4_private
{
  icd_nw_watch_pid_fn watch_fn;
  gpointer watch_fn_token;
  icd_nw_close_fn close_fn;
  icd_nw_status_change_fn status_change_fn;
  GSList *network_data_list;
};
typedef struct _ipv4_private ipv4_private;

struct _ipv4_network_data
{
  gchar *network_type;
  guint network_attrs;
  gchar *network_id;
  gchar *interface_name;
  gboolean use_dhcp;
  pid_t pid;
  gchar *ipv4_address;
  gchar *ipv4_netmask;
  gchar *ipv4_gateway;
  gchar *ipv4_dns1;
  gchar *ipv4_dns2;
  gchar *ipv4_dns3;
  time_t time_activated;
  guint rx_packets;
  guint tx_packets;
  guint rx_bytes;
  guint tx_bytes;
  gboolean configured;
  icd_nw_ip_up_cb_fn ip_up_cb;
  gpointer ip_up_cb_token;
  icd_nw_layer_renew_cb_fn renew_cb;
  gpointer renew_cb_token;
  gboolean dhcp;
  gboolean linklocal;
  guint ipv4_down_timeout;
  icd_nw_ip_down_cb_fn ip_down_cb;
  gpointer ip_down_cb_token;
  gboolean ignore_first_fail;
  gboolean shutting_down;
  gpointer private;
};
typedef struct _ipv4_network_data ipv4_network_data;

struct _ipv4_ipinfo
{
  struct in_addr addr;
  struct in_addr netmask;
  struct in_addr gateway;
  struct in_addr dns[2];
};

typedef struct _ipv4_ipinfo ipv4_ipinfo;

static const char *method = NULL;

static gboolean
string_equal(const char *a, const char *b)
{
  if (!a)
    return !b;

  if (b)
    return !strcmp(a, b);

  return FALSE;
}

static ipv4_network_data *
icd_ipv4_find_network_data(const gchar *network_type, guint network_attrs,
                           const gchar *network_id, ipv4_private *private)
{
  GSList *l;

  for (l = private->network_data_list; l; l = l->next)
  {
    ipv4_network_data *found = (ipv4_network_data *)l->data;

    if (!found)
      ILOG_WARN("ipv4 network data is NULL");
    else
    {
      if (found->network_attrs == network_attrs &&
          string_equal(found->network_type, network_type) &&
          string_equal(found->network_id, network_id))
      {
        return found;
      }
    }
  }

  return NULL;
}

static void
call_renew_cb(ipv4_network_data *network_data, gboolean changes_made)
{
  if (network_data->renew_cb)
  {
    gpointer renew_cb_token = network_data->renew_cb_token;
    enum icd_nw_renew_status status =
        (changes_made ? ICD_NW_RENEW_CHANGES_MADE : ICD_NW_RENEW_NO_CHANGES);

    network_data->renew_cb_token = NULL;
    network_data->renew_cb = NULL;
    network_data->renew_cb(status, renew_cb_token);
  }
  else
    ILOG_WARN("ipv4 network data NULL when calling renew callback");
}

static void
icd_ipv4_ip_renew(const gchar *network_type, guint network_attrs,
                  const gchar *network_id, icd_nw_layer_renew_cb_fn renew_cb,
                  gpointer renew_cb_token, gpointer *private)
{
  ipv4_network_data *network_data =
      icd_ipv4_find_network_data(network_type, network_attrs, network_id,
                                 *private);

  if (!network_data)
  {
    ILOG_INFO("ipv4 has no network for %s/%0x/%s when renew requested",
              network_type, network_attrs, network_id);
    renew_cb(ICD_NW_RENEW_NO_CHANGES, renew_cb_token);
    return;
  }

  if (network_data->renew_cb)
  {
    ILOG_WARN("ipv4 already renewing network %s/%0x/%s, ignoring",
              network_type, network_attrs, network_id);
    return;
  }

  ILOG_DEBUG("ipv4 trying to renew udhcpc lease");
  network_data->renew_cb = renew_cb;
  network_data->renew_cb_token = renew_cb_token;

  if (kill(network_data->pid, SIGUSR1))
  {
      ILOG_ERR("ipv4 could not send SIGUSR1 to dhcp pid %d: %s",
               network_data->pid, strerror(errno));
  }

    call_renew_cb(network_data, TRUE);
}

static void
icd_ipv4_ip_addr_info(const gchar *network_type, guint network_attrs,
                      const gchar *network_id, gpointer *private,
                      icd_nw_ip_addr_info_cb_fn cb,
                      const gpointer addr_info_cb_token)
{
  ipv4_network_data *network_data =
      icd_ipv4_find_network_data(network_type, network_attrs, network_id,
                                 *private);

  if (network_data)
  {
    if (network_data->configured)
    {
      cb(addr_info_cb_token, network_type, network_attrs, network_id,
        network_data->ipv4_address, network_data->ipv4_netmask,
        network_data->ipv4_gateway, network_data->ipv4_dns1,
        network_data->ipv4_dns2, network_data->ipv4_dns3);
    }
    else
    {
      ILOG_INFO("ipv4 not configured while address info requested");
      cb(addr_info_cb_token, network_type, network_attrs, network_id, NULL,
         NULL, NULL, NULL, NULL, NULL);
    }
  }
  else
  {
    ILOG_INFO("ipv4 has no network for %s/%0x/%s when address info requested",
              network_type, network_attrs, network_id);
    cb(addr_info_cb_token, network_type, network_attrs, network_id, NULL,
       NULL, NULL, NULL, NULL, NULL);
  }
}

gboolean
ipv4_stats_get(const gchar *interface, guint *rx_packets, guint *tx_packets,
               guint *rx_bytes, guint *tx_bytes)
{
  FILE *fp;
  char *p;
  char *q;
  char c;
  char s[256];
  unsigned int u;

  fp = fopen("/proc/net/dev", "r");

  if (!fp)
    return FALSE;

  fgets(s, sizeof(s), fp);
  fgets(s, sizeof(s), fp);

  if (!strstr(s, "compressed"))
  {
    fclose(fp);
    return FALSE;
  }

  do
  {
    if (!fgets(s, sizeof(s), fp))
      goto err;

    p = strrchr(s, ':');

    if (s[0] == ' ')
    {
      q = s;

      do
        c = (q++)[1];
      while (c == ' ');
    }
    else
      q = s;
  }
  while (p && strncmp(q, interface, p - q));

  if (!p)
    goto err;

  if (sscanf(p + 1, "%u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u", rx_bytes,
             rx_packets, &u, &u, &u, &u, &u, &u, tx_bytes, tx_packets, &u, &u,
             &u, &u, &u, &u) != 16)
  {
    goto err;
  }

  fclose(fp);
  return TRUE;

err:
  fclose(fp);

  return FALSE;
}

static void
icd_ipv4_ip_stats(const gchar *network_type, guint network_attrs,
                  const gchar *network_id, gpointer *private,
                  icd_nw_ip_stats_cb_fn cb, const gpointer ip_stats_cb_token)
{
  ipv4_private *priv = (ipv4_private *)*private;
  ipv4_network_data *network_data;
  guint rx_bytes = 0;
  guint tx_bytes = 0;
  guint tx_packets;
  guint rx_packets;

  network_data = icd_ipv4_find_network_data(network_type, network_attrs,
                                            network_id, priv);

  if (network_data)
  {
    if (network_data->configured)
    {
      ipv4_stats_get(network_data->interface_name, &rx_packets, &tx_packets,
                     &rx_bytes, &tx_bytes);
      cb(ip_stats_cb_token, network_type, network_attrs, network_id,
         time(0) - network_data->time_activated,
         rx_bytes - network_data->rx_bytes,
         tx_bytes - network_data->tx_bytes);
    }
    else
    {
      ILOG_INFO("ipv4 not configured while stats requested");
      cb(ip_stats_cb_token, network_type, network_attrs, network_id, 0, 0, 0);
    }
  }
  else
  {
    ILOG_INFO("ipv4 has no network for %s/%0x/%s when stats requested",
              network_type, network_attrs, network_id);
    cb(ip_stats_cb_token, network_type, network_attrs, network_id, 0, 0, 0);
  }
}

static void
icd_ipv4_exec_network_script(const gchar *script_param)
{
  execl("/bin/sh", "/bin/sh", "/etc/udhcpc/libicd_network_ipv4.script",
        script_param, NULL);

  ILOG_CRIT("ipv4 static script with parameter '%s' could not run: %s",
            script_param, strerror(errno));

  exit(1);
}

static void
icd_ipv4_set_env(ipv4_network_data *network_data)
{
  gchar *dns1 = "";
  gchar *dns2 = "";
  gchar *dns3 = "";

  setenv("interface", network_data->interface_name, TRUE);
  setenv("ip", network_data->ipv4_address, TRUE);
  setenv("subnet", network_data->ipv4_netmask, TRUE);

  if (network_data->ipv4_gateway)
    setenv("router", network_data->ipv4_gateway, TRUE);

  if (network_data->ipv4_dns1)
  {
    gchar *dns;

    dns1 = network_data->ipv4_dns1;

    if (network_data->ipv4_dns2)
      dns2 = network_data->ipv4_dns2;

    if (network_data->ipv4_dns3)
      dns3 = network_data->ipv4_dns3;

    dns = g_strdup_printf("%s %s %s", dns1, dns2, dns3);
    setenv("dns", dns, TRUE);
    g_free(dns);
  }
}

static void
icd_ipv4_set_env_and_deconfig(ipv4_network_data *network_data)
{
  if (!fork())
  {
    icd_ipv4_set_env(network_data);
    icd_ipv4_exec_network_script("deconfig");
  }
}

static void
icd_ipv4_clear_network_data(ipv4_network_data *network_data)
{
  if (network_data->ipv4_down_timeout)
    g_source_remove(network_data->ipv4_down_timeout);

  g_free(network_data->network_id);

  if (network_data->interface_name)
  {
    gchar *resolv_conf_file = g_strdup_printf("/tmp/resolv.conf.%s",
                                              network_data->interface_name);
    ILOG_DEBUG("ipv4 removing '%s'", resolv_conf_file);
    unlink(resolv_conf_file);
    g_free(resolv_conf_file);
  }

  g_free(network_data->interface_name);
  g_free(network_data->network_type);
  g_free(network_data->ipv4_address);
  g_free(network_data->ipv4_netmask);
  g_free(network_data->ipv4_gateway);
  g_free(network_data->ipv4_dns1);
  g_free(network_data->ipv4_dns2);
  g_free(network_data->ipv4_dns3);
  g_free(network_data);
}

static gboolean
ipv4_down_cb(gpointer user_data)
{
  ipv4_network_data *network_data = (ipv4_network_data *)user_data;
  network_data->ipv4_down_timeout = 0;

  if (kill(network_data->pid, SIGTERM))
  {
    ipv4_private *priv = (ipv4_private *)network_data->private;

    ILOG_ERR("ipv4 could not send SIGTERM to dhcp pid %d: %s",
             network_data->pid, strerror(errno));

    priv->network_data_list = g_slist_remove(priv->network_data_list,
                                             network_data);

    ILOG_DEBUG("ipv4 down cb called");
    network_data->ip_down_cb(0, network_data->ip_down_cb_token);

    icd_ipv4_clear_network_data(network_data);
  }
  else
    ILOG_INFO("ipv4 sent SIGTERM to dhcp pid %d", network_data->pid);

  return FALSE;
}

static void
icd_ipv4_ip_down(const gchar *network_type, guint network_attrs,
                 const gchar *network_id, const gchar *interface_name,
                 icd_nw_ip_down_cb_fn ip_down_cb, gpointer ip_down_cb_token,
                 gpointer *private)
{
  ipv4_private *priv = (ipv4_private *)*private;

  ipv4_network_data *network_data =
      icd_ipv4_find_network_data(network_type, network_attrs, network_id, priv);

  if (!network_data)
  {
    ILOG_INFO("ipv4 has no data for network %s/%0x/%s", network_type,
              network_attrs, network_id);
    ip_down_cb(ICD_NW_SUCCESS, ip_down_cb_token);
    return;
  }

  if (!network_data->pid)
  {
    ILOG_INFO("ipv4 has no child processes running for %s/%0x/%s", network_type,
              network_attrs, network_id);

    if (!network_data->use_dhcp)
      icd_ipv4_set_env_and_deconfig(network_data);

    priv->network_data_list = g_slist_remove(priv->network_data_list,
                                             network_data);
    icd_ipv4_clear_network_data(network_data);
    ip_down_cb(ICD_NW_SUCCESS, ip_down_cb_token);
    return;
  }

  network_data->ip_down_cb = ip_down_cb;
  network_data->ip_down_cb_token = ip_down_cb_token;
  network_data->shutting_down = TRUE;

  if (network_data->use_dhcp)
  {
    ILOG_INFO("ipv4 releasing dhcp lease for pid %d", network_data->pid);

    if (kill(network_data->pid, SIGUSR2))
    {
      ILOG_ERR("ipv4 could not send SIGUSR2 to dhcp pid %d: %s",
               network_data->pid, strerror(errno));
    }

    if (network_data->ipv4_down_timeout)
      g_source_remove(network_data->ipv4_down_timeout);

    network_data->ipv4_down_timeout =
        g_timeout_add(500, ipv4_down_cb, network_data);
  }
  else
  {
    ILOG_INFO("ipv4 stopping static configuration pid %d", network_data->pid);

    if (kill(network_data->pid, SIGTERM))
    {
      ILOG_ERR("ipv4 could not send SIGTERM to %d: %s", network_data->pid,
               strerror(errno));
      priv->network_data_list = g_slist_remove(priv->network_data_list,
                                               network_data);
      icd_ipv4_set_env_and_deconfig(network_data);
      ip_down_cb(ICD_NW_SUCCESS, ip_down_cb_token);
      icd_ipv4_clear_network_data(network_data);
    }
  }
}

static gboolean
icd_ipv4_get_dns(ipv4_network_data *network_data)
{
  network_data->ipv4_dns1 =
      _icd_gconf_get_iap_string(network_data->network_id, "ipv4_dns1");
  network_data->ipv4_dns2 =
      _icd_gconf_get_iap_string(network_data->network_id, "ipv4_dns2");
  network_data->ipv4_dns3 =
      _icd_gconf_get_iap_string(network_data->network_id, "ipv4_dns3");

  if (network_data->ipv4_dns1 || network_data->ipv4_dns2 ||
      network_data->ipv4_dns3)
  {
    return TRUE;
  }

  return FALSE;
}

static void
icd_ipv4_exec_static_ip(ipv4_network_data *network_data)
{
  network_data->ipv4_address =
      _icd_gconf_get_iap_string(network_data->network_id, "ipv4_address");
  network_data->ipv4_netmask =
      _icd_gconf_get_iap_string(network_data->network_id, "ipv4_netmask");
  network_data->ipv4_gateway =
      _icd_gconf_get_iap_string(network_data->network_id, "ipv4_gateway");
  icd_ipv4_get_dns(network_data);

  if (network_data->ipv4_address && *network_data->ipv4_address)
  {
    if (network_data->ipv4_netmask && *network_data->ipv4_netmask)
    {
      network_data->pid = fork();

      if (network_data->pid < 0)
      {
        ILOG_ERR("ipv4 fork failed while setting static addresses - %s",
                 strerror(errno));
      }
      else
      {
        if (!network_data->pid)
        {
          icd_ipv4_set_env(network_data);
          icd_ipv4_exec_network_script("static");
        }

        ILOG_INFO(
              "ipv4 attempting to configure %s %s/%s gw %s dns %s, %s, %s",
              network_data->interface_name, network_data->ipv4_address,
              network_data->ipv4_netmask, network_data->ipv4_gateway,
              network_data->ipv4_dns1, network_data->ipv4_dns2,
              network_data->ipv4_dns3);
      }
    }
  }
}

static gboolean
icd_ipv4_append_nameserver(int fd, const char *dns)
{
  gchar *s;
  size_t len;
  ssize_t bytes;

  if (!dns || !strcmp(dns, "0.0.0.0"))
    return FALSE;

  s = g_strdup_printf("nameserver %s\n", dns);
  len = strlen(s);
  bytes = write(fd, s, len);
  g_free(s);

  return len == bytes;
}

static void
icd_ipv4_set_dns(ipv4_network_data *network_data)
{
  icd_ipv4_get_dns(network_data);

  if (network_data->interface_name)
  {
    gchar *resolv_conf_name = g_strdup_printf("/tmp/resolv.conf.%s",
                                              network_data->interface_name);
    int fd = creat(resolv_conf_name, 0444);

    if (fd == -1)
    {
      ILOG_ERR("ipv4 could not create '%s': %s", resolv_conf_name,
               strerror(errno));
    }
    else
    {
      if (icd_ipv4_append_nameserver(fd, network_data->ipv4_dns1) ||
          icd_ipv4_append_nameserver(fd, network_data->ipv4_dns2) ||
          icd_ipv4_append_nameserver(fd, network_data->ipv4_dns3))
      {
        ILOG_DEBUG("ipv4 wrote '%s'", resolv_conf_name);
      }
      else
      {
        ILOG_ERR("ipv4 could not write dns srv into '%s'",
                 resolv_conf_name);
      }

      close(fd);
    }

    g_free(resolv_conf_name);
  }
}

static void
icd_ipv4_exec_dhcp(ipv4_network_data *network_data)
{
  char hostname[64];

  if (gethostname(hostname, sizeof(hostname)))
    *hostname = 0;

  network_data->pid = fork();

  if (network_data->pid < 0)
    ILOG_ERR("ipv4 fork failed while starting dhcp client %s", strerror(errno));
  else
  {
    if (!network_data->pid)
    {
      if (*hostname)
      {
        execl("/sbin/udhcpc", "/sbin/udhcpc",
              "-i", network_data->interface_name,
              "-s", "/etc/udhcpc/libicd_network_ipv4.script",
              "-H", hostname, "-f", "-R", "15", NULL);
      }
      else
      {
        execl("/sbin/udhcpc", "/sbin/udhcpc",
              "-i", network_data->interface_name,
              "-s", "/etc/udhcpc/libicd_network_ipv4.script",
              "-f", "-R", "15", NULL);
      }

      exit(1);
    }

    ILOG_INFO("ipv4 attempting to configure %s via dhcp",
              network_data->interface_name);
  }
}

static void
icd_ipv4_ip_up(const gchar *network_type, const guint network_attrs,
               const gchar *network_id, const gchar *interface_name,
               icd_nw_ip_up_cb_fn ip_up_cb, gpointer ip_up_cb_token,
               gpointer *privatx)
{
  ipv4_private *priv = (ipv4_private *)*privatx;
  ipv4_network_data *network_data;

  if (!priv)
  {
    ILOG_CRIT("ipv4 ip_up called with NULL private data");
    ip_up_cb(ICD_NW_ERROR, ICD_DBUS_ERROR_SYSTEM_ERROR, ip_up_cb_token, NULL);
    return;
  }

  if (!interface_name || !*interface_name)
  {
    ILOG_ERR("ipv4 did not get interface name");
    ip_up_cb(ICD_NW_ERROR, ICD_DBUS_ERROR_SYSTEM_ERROR, ip_up_cb_token, NULL);
    return;
  }

  network_data = g_new0(ipv4_network_data, 1);
  network_data->ip_up_cb = ip_up_cb;
  network_data->ip_up_cb_token = ip_up_cb_token;
  network_data->network_type = g_strdup(network_type);
  network_data->network_attrs = network_attrs;
  network_data->network_id = g_strdup(network_id);
  network_data->private = priv;
  network_data->ignore_first_fail = TRUE;
  network_data->use_dhcp = TRUE;
  network_data->interface_name = g_strdup(interface_name);

  if (network_attrs & ICD_NW_ATTR_IAPNAME)
  {
    gchar *ipv4_type = _icd_gconf_get_iap_string(network_id, "ipv4_type");

    if (ipv4_type && !strcasecmp(ipv4_type, "STATIC"))
      network_data->use_dhcp = FALSE;

    g_free(ipv4_type);
  }

  ipv4_stats_get(network_data->interface_name, &network_data->rx_packets,
                 &network_data->tx_packets, &network_data->rx_bytes,
                 &network_data->tx_bytes);

  if (!network_data->use_dhcp)
    icd_ipv4_exec_static_ip(network_data);
  else
  {
    gboolean ipv4_autodns =
        _icd_gconf_get_iap_bool(network_data->network_id, "ipv4_autodns", TRUE);

    ILOG_DEBUG("ipv4 dns autoconfig is %d", ipv4_autodns);

    if ((network_data->network_attrs & ICD_NW_ATTR_IAPNAME) && !ipv4_autodns)
      icd_ipv4_set_dns(network_data);

    icd_ipv4_exec_dhcp(network_data);
  }

  ILOG_DEBUG("ipv4 child pid %d", network_data->pid);

  if (network_data->pid <= 0)
  {
    ILOG_ERR("ipv4 ip_up could not start %s",
             network_data->use_dhcp ?
               "DHCP client" :
               "static address configuration");

    ip_up_cb(ICD_NW_ERROR, ICD_DBUS_ERROR_SYSTEM_ERROR, ip_up_cb_token, NULL);
    icd_ipv4_clear_network_data(network_data);
  }
  else
  {
    priv->network_data_list =
        g_slist_prepend(priv->network_data_list, network_data);
    priv->watch_fn(network_data->pid, priv->watch_fn_token);
  }
}

void
icd_ipv4_child_exit(const pid_t pid, const gint exit_value, gpointer *private)
{
  ipv4_private *priv = (ipv4_private *)*private;
  GSList *l;
  ipv4_network_data *network_data;

  for (l = priv->network_data_list; l; l = l->next)
  {
    network_data = (ipv4_network_data *)l->data;

    if (network_data)
    {
      if (pid == network_data->pid)
        break;
    }
    else
      ILOG_WARN("ipv4 network data is NULL when searching for pid");
  }

  if (!l)
  {
    ILOG_ERR("ipv4 got child exit for %d, but network data is NULL", pid);
    return;
  }

  network_data->pid = 0;

  if (network_data->use_dhcp)
  {
    if (network_data->shutting_down)
    {
      ILOG_INFO("ipv4 dhcp client pid %d exited with value %d", pid,
                exit_value);

      priv->network_data_list = g_slist_remove(priv->network_data_list,
                                               network_data);
      network_data->ip_down_cb(ICD_NW_SUCCESS, network_data->ip_down_cb_token);
      icd_ipv4_clear_network_data(network_data);
    }
    else
    {
      ILOG_INFO("ipv4 dhcp client pid %d exited with value %d, shutting down network %s/%0x/%s",
                pid, exit_value, network_data->network_type,
                network_data->network_attrs, network_data->network_id);

      if (network_data->configured)
      {
        priv->close_fn(ICD_NW_ERROR, ICD_DBUS_ERROR_SYSTEM_ERROR,
                       network_data->network_type, network_data->network_attrs,
                       network_data->network_id);
      }
      else
      {
        const char *err_str;

        if (network_data->network_attrs & 0x10) /* FIXME */
          err_str = ICD_DBUS_ERROR_DHCP_WEP_FAILED;
        else
          err_str = ICD_DBUS_ERROR_DHCP_FAILED;

        priv->close_fn(ICD_NW_ERROR, err_str, network_data->network_type,
                       network_data->network_attrs, network_data->network_id);
      }
    }
  }
  else if (network_data->shutting_down)
  {
    ILOG_INFO(
          "ipv4 got child exit for %d when shutting down static configuration",
          pid);
    priv->network_data_list = g_slist_remove(priv->network_data_list, network_data);
    icd_ipv4_set_env_and_deconfig(network_data);
    network_data->ip_down_cb(ICD_NW_SUCCESS, network_data->ip_down_cb_token);
    icd_ipv4_clear_network_data(network_data);
  }
  else
  {
    ILOG_INFO("ipv4 static configuration pid %d exited with value %d", pid,
              exit_value);
  }
}

static gboolean
ipv4_get_iface_addr_netmask(const char *ifname, ipv4_ipinfo *ipinfo)
{
  int fd;
  struct ifreq ifr;

  fd = socket(AF_INET, SOCK_DGRAM, 0);

  if (fd == -1)
    return FALSE;

  ILOG_DEBUG("ipv4 trying '%s'", ifname);

  ifr.ifr_addr.sa_family = AF_INET;
  strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

  if (ioctl(fd, SIOCGIFADDR, &ifr) == -1)
    goto err;

  ipinfo->addr = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;

  ifr.ifr_addr.sa_family = AF_INET;
  strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

  if (ioctl(fd, SIOCGIFNETMASK, &ifr) == -1)
    goto err;

  ipinfo->netmask = ((struct sockaddr_in *)&ifr.ifr_netmask)->sin_addr;
  close(fd);
  return TRUE;

err:
  close(fd);

  return FALSE;
}

static gboolean
icd_ipv4_connected(ipv4_network_data *network_data)
{
  if (network_data->configured)
    return FALSE;

  network_data->time_activated = time(0);

  if (network_data->ipv4_down_timeout)
  {
    ILOG_DEBUG("stopped dhcp SIGTERM timeout since we got connected");
    g_source_remove(network_data->ipv4_down_timeout);
  }

  network_data->configured = TRUE;

  if (network_data->use_dhcp)
    method = "METHOD=dhcp";
  else
    method = "METHOD=static";

  network_data->ip_up_cb(0, 0, network_data->ip_up_cb_token);

  return TRUE;
}

static void
icd_ipv4_inet_ntop(struct in_addr addr, gchar **buf)
{
  g_free(*buf);

  *buf = g_new0(char, INET_ADDRSTRLEN);

  if (!inet_ntop(AF_INET, &addr, *buf, INET_ADDRSTRLEN))
  {
    g_free(*buf);
    *buf = NULL;
  }
}

static gboolean
icd_ipv4_ip_info_dns(const char *fname, ipv4_ipinfo *ipinfo)
{
  FILE *fp;
  int i = 0;
  char buf[256];

  ipinfo->dns[0].s_addr = 0;
  ipinfo->dns[1].s_addr = 0;

  if (!fname)
    return FALSE;

  ILOG_DEBUG("ipv4 trying '%s'", fname);

  fp = fopen(fname, "r");

  if (!fp)
    return FALSE;

  while (fgets(buf, sizeof(buf), fp) && i <= 1 )
  {
    if (!strncmp(buf, "nameserver ", 11))
    {
      if (inet_aton(&buf[11], &ipinfo->dns[i]))
        i++;
    }
  }

  fclose(fp);

  return TRUE;
}

void
ipv4_ip_get_ipinfo(const char *ifname, const char *ifindex, ipv4_ipinfo *ipinfo)
{
  gchar *iface;
  FILE *fp;
  gchar *resolv_conf_name;
  char buf[256];
  char gateway[128];
  int flags;

  if (ifindex)
    iface = g_strdup_printf("%s:%s", ifname, ifindex);
  else
    iface = NULL;

  if (!ipv4_get_iface_addr_netmask(ifname, ipinfo))
  {
    if (iface)
      ipv4_get_iface_addr_netmask(iface, ipinfo);
  }

  fp = fopen("/proc/net/route", "r");

  if (fp)
  {
    fgets(buf, 256, fp);

    while (fgets(buf, sizeof(buf), fp))
    {
      if (sscanf(buf, "%*16s %*128s %128s %X %*d %*d %*d %*127s %*d %*d %*d\n",
                 gateway, &flags) > 1 &&
          (flags & (RTF_UP | RTF_GATEWAY)) == (RTF_UP | RTF_GATEWAY))
      {
        ipinfo->gateway.s_addr = strtoul(gateway, NULL, 16);
        fclose(fp);
        goto get_dns;
      }
    }

    ipinfo->gateway.s_addr = 0;
    fclose(fp);
  }

get_dns:
  resolv_conf_name = g_strconcat("/tmp/resolv.conf", ".", ifname, NULL);

  if (!icd_ipv4_ip_info_dns(resolv_conf_name, ipinfo))
  {
    gboolean dns_got = FALSE;

    if (iface)
    {
      g_free(resolv_conf_name);
      resolv_conf_name = g_strconcat("/tmp/resolv.conf", ".", iface, NULL);
      dns_got = icd_ipv4_ip_info_dns(resolv_conf_name, ipinfo);
    }

    if (!dns_got)
      icd_ipv4_ip_info_dns("/tmp/resolv.conf", ipinfo);
  }

  g_free(resolv_conf_name);
  g_free(iface);
}

static void
icd_ipv4_update_ip_info(ipv4_network_data *network_data)
{
  ipv4_ipinfo *ipinfo = g_new0(ipv4_ipinfo, 1);

  ILOG_DEBUG("ipv4 updating ip info");

  ipv4_ip_get_ipinfo(network_data->interface_name, "1", ipinfo);

  icd_ipv4_inet_ntop(ipinfo->addr, &network_data->ipv4_address);
  icd_ipv4_inet_ntop(ipinfo->netmask, &network_data->ipv4_netmask);
  icd_ipv4_inet_ntop(ipinfo->gateway, &network_data->ipv4_gateway);
  icd_ipv4_inet_ntop(ipinfo->dns[0], &network_data->ipv4_dns1);
  icd_ipv4_inet_ntop(ipinfo->dns[1], &network_data->ipv4_dns2);

  g_free(network_data->ipv4_dns3);
  network_data->ipv4_dns3 = NULL;

  g_free(ipinfo);
}

static DBusHandlerResult
icd_ipv4_autoconf_cb(DBusConnection *connection, DBusMessage *message,
            gpointer user_data)
{
  ipv4_private *priv = (ipv4_private *)user_data;
  GSList *l;
  ipv4_network_data *network_data;
  gchar *ipv4_address_old;
  gboolean got_new_addr;
  gboolean v25;
  const char *state;
  const char *application;
  const char *interface;

  if (!dbus_message_is_signal(message, ICD_DBUS_AUTOCONF_INTERFACE,
                              ICD_AUTOCONF_CHANGED_SIG) &&
      !dbus_message_is_method_call(message, ICD_DBUS_AUTOCONF_INTERFACE,
                                   ICD_AUTOCONF_CHANGED_SIG))
  {
    return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
  }

  if (!dbus_message_get_args(message, NULL,
                             DBUS_TYPE_STRING, &interface,
                             DBUS_TYPE_STRING, &application,
                             DBUS_TYPE_STRING, &state,
                             DBUS_TYPE_INVALID))
  {
    ILOG_WARN("ipv4 could not get args from autoconf message");
    return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
  }


  if (strcasecmp(application, "DHCP") && strcasecmp(application, "LINKLOCAL"))
  {
    ILOG_DEBUG("ipv4 module does not handle application '%s' autoconf",
               application);
    return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
  }

  for (l = priv->network_data_list; l; l = l->next)
  {
    network_data = (ipv4_network_data *)l->data;

    if (network_data)
    {
      if (!strcmp(interface, network_data->interface_name))
        break;
    }
    else
      ILOG_WARN("ipv4 network data is NULL when searching for interface");
  }

  if ( !l )
  {
    ILOG_WARN("ipv4 has not configured interface '%s'", interface);
    return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
  }

  if (network_data->shutting_down)
  {
    ILOG_DEBUG("ipv4 got autoconf signal while shutting down, ignoring them");
    return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
  }

  if (!strcasecmp(application, "DHCP"))
    network_data->dhcp = !strcasecmp(state, "CONNECTED");

  if (!strcasecmp(application, "LINKLOCAL"))
    network_data->linklocal = !strcasecmp(state, "CONNECTED");

  ILOG_INFO("ipv4 got autoconf signal with args '%s' '%s' '%s', dhcp %d, linklocal %d",
            interface, application, state, network_data->dhcp,
            network_data->linklocal);

  ipv4_address_old = g_strdup(network_data->ipv4_address);

  icd_ipv4_update_ip_info(network_data);

  if (ipv4_address_old)
    got_new_addr = !string_equal(ipv4_address_old, network_data->ipv4_address);
  else
    got_new_addr = FALSE;

  if (network_data->renew_cb)
  {
    if (got_new_addr)
    {
      ILOG_DEBUG("ipv4 renewed address %s, got new address %s instead",
                 ipv4_address_old, network_data->ipv4_address);

      call_renew_cb(network_data, TRUE);
    }
    else
    {
      ILOG_DEBUG("ipv4 renewed address %s", network_data->ipv4_address);
      call_renew_cb(network_data, FALSE);
    }

    g_free(ipv4_address_old);

    return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
  }

  g_free(ipv4_address_old);

  if (!network_data->dhcp)
  {
    if (network_data->linklocal)
    {
      if (!strcasecmp(network_data->network_type, "WLAN_INFRA"))
      {
        GConfClient *gconf = gconf_client_get_default();

        v25 = gconf_client_get_bool(gconf, ICD_GCONF_LINKLOCAL_WLAN_INFRA, NULL);
        g_object_unref(gconf);

        if ( !v25 )
          goto LABEL_54;
      }
      else if (strcasecmp(network_data->network_type, "WLAN_ADHOC"))
      {
        goto LABEL_54;
      }

      if (!icd_ipv4_connected(network_data))
      {
        ILOG_INFO("ipv4 got again a linklocal autoconf signal");
        priv->status_change_fn(network_data->network_type,
                               network_data->network_attrs,
                               network_data->network_id);
      }
    }
    else
    {
LABEL_54:
      if (network_data->ignore_first_fail)
        ILOG_INFO("ipv4 ignored first unsuccessful autoconf message");
      else
      {
        ILOG_INFO("ipv4 link local not configured or allowed");

        if (network_data->linklocal || network_data->dhcp)
        {
          priv->close_fn(ICD_NW_ERROR, NULL, network_data->network_type,
                         network_data->network_attrs, network_data->network_id);
        }
        else
        {
          const char *err_str;

          if (network_data->network_attrs & 0x10)
            err_str = ICD_DBUS_ERROR_DHCP_WEP_FAILED;
          else
            err_str = ICD_DBUS_ERROR_DHCP_FAILED;

          priv->close_fn(ICD_NW_ERROR, err_str, network_data->network_type,
                         network_data->network_attrs, network_data->network_id);
        }
      }
    }

    network_data->ignore_first_fail = FALSE;
    return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
  }

  if (!icd_ipv4_connected(network_data) && !network_data->dhcp)
  {
    ILOG_INFO("ipv4 got a dhcp lease again");

    if (got_new_addr)
    {
      ILOG_INFO("ipv4 address changed, restart");
      priv->close_fn(ICD_NW_RESTART_IP, NULL, network_data->network_type,
                     network_data->network_attrs, network_data->network_id);
    }
    else
    {
      priv->status_change_fn(network_data->network_type,
                             network_data->network_attrs, network_data->network_id);
    }
  }

  return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static void
icd_ipv4_network_destruct(gpointer *private)
{
  ipv4_private *priv = *private;

  if (priv->network_data_list)
    ILOG_CRIT("ipv4 still has connected networks");

  icd_dbus_disconnect_system_bcast_signal(
        ICD_DBUS_AUTOCONF_INTERFACE, icd_ipv4_autoconf_cb, priv,
        "member='" ICD_AUTOCONF_CHANGED_SIG "'");
  g_free(priv);
  *private = NULL;
}

gboolean
icd_nw_init(struct icd_nw_api *network_api, icd_nw_watch_pid_fn watch_fn,
            gpointer watch_fn_token, icd_nw_close_fn close_fn,
            icd_nw_status_change_fn status_change_fn, icd_nw_renew_fn renew_fn)
{
  ipv4_private *priv = priv = g_new0(ipv4_private, 1);

  network_api->version = ICD_NW_MODULE_VERSION;
  network_api->ip_up = icd_ipv4_ip_up;
  network_api->ip_down = icd_ipv4_ip_down;
  network_api->ip_addr_info = icd_ipv4_ip_addr_info;
  network_api->ip_stats = icd_ipv4_ip_stats;
  network_api->child_exit = icd_ipv4_child_exit;
  network_api->network_destruct = icd_ipv4_network_destruct;
  network_api->ip_renew = icd_ipv4_ip_renew;
  network_api->private = priv;
  priv->watch_fn = watch_fn;
  priv->watch_fn_token = watch_fn_token;
  priv->close_fn = close_fn;
  priv->status_change_fn = status_change_fn;

  if (icd_dbus_connect_system_bcast_signal(
        ICD_DBUS_AUTOCONF_INTERFACE, icd_ipv4_autoconf_cb, priv,
        "member='" ICD_AUTOCONF_CHANGED_SIG "'"))
  {
    return TRUE;
  }

  ILOG_ERR("ipv4 module could not register autoconf signal reception");

  network_api->private = NULL;
  g_free(priv);

  return FALSE;
}

/* XXX - fmg: This code is copied from idc_gconf.c, maybe it is a good idea to
 * make it public someday
 */
static void
_icd_gconf_check_error(GError **error)
{
  if (error && *error)
  {
    ILOG_ERR("icd gconf error: %s", (*error)->message);
    g_clear_error(error);
    *error = NULL;
  }
}

static gchar *
_icd_gconf_get_iap_string(const char *iap_name, const char *key_name)
{
  GConfClient *gconf = gconf_client_get_default();
  GError *err = NULL;
  char *id = gconf_escape_key(iap_name, -1);
  gchar *key = g_strdup_printf(ICD_GCONF_PATH "/%s/%s", id, key_name);
  gchar *rv;

  g_free(id);
  rv = gconf_client_get_string(gconf, key, &err);
  g_free(key);
  _icd_gconf_check_error(&err);
  g_object_unref(gconf);

  return rv;
}

static gboolean
_icd_gconf_get_iap_bool(const char *iap_name, const char *key_name,
                        gboolean def)
{
  GConfClient *gconf = gconf_client_get_default();
  gchar *key;
  GConfValue *val;
  gboolean rv = def;
  GError *err = NULL;

  if (iap_name)
  {
    gchar *s = gconf_escape_key(iap_name, -1);
    key = g_strdup_printf(ICD_GCONF_PATH  "/%s/%s", s, key_name);
    g_free(s);
  }
  else
    key = g_strdup_printf(ICD_GCONF_PATH "/%s", key_name);

  val = gconf_client_get(gconf, key, &err);
  g_free(key);
  _icd_gconf_check_error(&err);

  if (val)
  {
    if (G_VALUE_HOLDS_BOOLEAN(val))
      rv = gconf_value_get_bool(val);

    gconf_value_free(val);
  }

  g_object_unref(gconf);

  return rv;
}
