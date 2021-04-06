/*
 *  Advanced Linux Sound Architecture Control Program
 *  Copyright (c) by Takashi Iwai <tiwai@suse.de>
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

/*
 * ALSA Monitor (extended version)
 * Copyrigth (c) 2021 by Piotr Stolarz <pstolarz@o2.pl>
 */

#include <stddef.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <limits.h>
#include <time.h>
#include <signal.h>

#include <sys/epoll.h>
#include <sys/inotify.h>
#include <sys/signalfd.h>

#include <alsa/asoundlib.h>

#include "list.h"

struct src_entry {
    snd_ctl_t *handle;
    char *name;
    unsigned int pfd_count;
    struct list_head list;
};

struct snd_card_iterator {
    int card;
    char name[16];
};

void snd_card_iterator_init(struct snd_card_iterator *iter)
{
    iter->card = -1;
    memset(iter->name, 0, sizeof(iter->name));
}

static const char *snd_card_iterator_next(struct snd_card_iterator *iter)
{
    if (snd_card_next(&iter->card) < 0)
        return NULL;
    if (iter->card < 0)
        return NULL;

    snprintf(iter->name, sizeof(iter->name), "hw:%d", iter->card);

    return (const char *)iter->name;
}

static void remove_source_entry(struct src_entry *entry)
{
    list_del(&entry->list);
    if (entry->handle)
        snd_ctl_close(entry->handle);
    free(entry->name);
    free(entry);
}

static void clear_source_list(struct list_head *srcs)
{
    struct src_entry *entry, *tmp;

    list_for_each_entry_safe(entry, tmp, srcs, list)
        remove_source_entry(entry);
}

static int insert_source_entry(struct list_head *srcs, snd_ctl_t *handle,
    const char *name)
{
    struct src_entry *entry;
    int count;
    int err;

    entry = calloc(1, sizeof(*entry));
    if (!entry)
        return -ENOMEM;
    INIT_LIST_HEAD(&entry->list);
    entry->handle = handle;

    entry->name = strdup(name);
    if (!entry->name) {
        err = -ENOMEM;
        goto error;
    }

    count = snd_ctl_poll_descriptors_count(handle);
    if (count < 0) {
        err = count;
        goto error;
    }
    if (count == 0) {
        err = -ENXIO;
        goto error;
    }
    entry->pfd_count = count;

    list_add_tail(&entry->list, srcs);

    return 0;
error:
    remove_source_entry(entry);
    return err;
}

static int open_ctl(const char *name, snd_ctl_t **ctlp)
{
    snd_ctl_t *ctl;
    int err;

    err = snd_ctl_open(&ctl, name, SND_CTL_READONLY);
    if (err < 0) {
        fprintf(stderr, "Cannot open ctl %s\n", name);
        return err;
    }
    err = snd_ctl_subscribe_events(ctl, 1);
    if (err < 0) {
        fprintf(stderr, "Cannot open subscribe events to ctl %s\n", name);
        snd_ctl_close(ctl);
        return err;
    }
    *ctlp = ctl;
    return 0;
}

static inline bool seek_entry_by_name(struct list_head *srcs, const char *name)
{
    struct src_entry *entry;

    list_for_each_entry(entry, srcs, list) {
        if (!strcmp(entry->name, name))
            return true;
    }

    return false;
}

static int prepare_source_entry(struct list_head *srcs, const char *name)
{
    snd_ctl_t *handle;
    int err;

    if (!name) {
        struct snd_card_iterator iter;
        const char *cardname;

        snd_card_iterator_init(&iter);
        while ((cardname = snd_card_iterator_next(&iter))) {
            if (seek_entry_by_name(srcs, cardname))
                continue;
            err = open_ctl(cardname, &handle);
            if (err < 0)
                return err;
            err = insert_source_entry(srcs, handle, cardname);
            if (err < 0)
                return err;
        }
    } else {
        if (seek_entry_by_name(srcs, name))
            return 0;
        err = open_ctl(name, &handle);
        if (err < 0)
            return err;
        err = insert_source_entry(srcs, handle, name);
        if (err < 0)
            return err;
    }

    return 0;
}

static int check_control_cdev(int infd, bool *retry)
{
    struct inotify_event *ev;
    char *buf;
    int err = 0;

    buf = calloc(1, sizeof(*ev) + NAME_MAX);
    if (!buf)
        return -ENOMEM;

    while (1) {
        ssize_t len = read(infd, buf, sizeof(*ev) + NAME_MAX);
        if (len < 0) {
            if (errno != EAGAIN)
                err = errno;
            break;
        } else if (len == 0) {
            break;
        }

        size_t pos = 0;
        while (pos < len) {
            ev = (struct inotify_event *)(buf + pos);
            if ((ev->mask & IN_CREATE) &&
                strstr(ev->name, "controlC") == ev->name)
                *retry = true;
            pos += sizeof(*ev) + ev->len;
        }
    }

    free(buf);

    return err;
}

static void dump_hex_bytes(
    const unsigned char *bytes, size_t len, const char *pref)
{
    static const char HEX[] = "0123456789abcdef";
    int i;

    for (i = 0; i < len;) {
        if (!(i % 16)) printf(pref);
        else if (!(i % 8)) putc(' ', stdout);
        else putc(':', stdout);

        putc(HEX[bytes[i] >> 4], stdout);
        putc(HEX[bytes[i++] & 0x0f], stdout);

        if (!(i % 16) || i >= len) putc('\n', stdout);
    }
}

static void dump_hex_ints(const unsigned *ints, size_t len, const char *pref)
{
    int i;

    for (i = 0; i < len;) {
        if (!(i % 4)) printf(pref);
        else if (!(i % 2)) putc(' ', stdout);
        else putc(':', stdout);

        printf("%08x", ints[i++]);

        if (!(i % 4) || i >= len) putc('\n', stdout);
    }
}

static int print_event(snd_ctl_t *ctl, const char *name)
{
    int err;
    snd_ctl_event_t *event;
    unsigned int i, numid, dev, subdev, mask, index, count;
    snd_ctl_elem_iface_t intf;
    snd_ctl_elem_type_t type;

    snd_ctl_elem_id_t *id;
    snd_ctl_elem_value_t *val;
    snd_ctl_elem_info_t *info;

    long int_min = 0, int_max = 0;
    unsigned int *db_tlv = NULL;
    unsigned int tlv[64] = {0};

    snd_ctl_event_alloca(&event);
    err = snd_ctl_read(ctl, event);
    if (err < 0) return err;

    if (snd_ctl_event_get_type(event) != SND_CTL_EVENT_ELEM)
        return 0;

    numid = snd_ctl_event_elem_get_numid(event);
    intf = snd_ctl_event_elem_get_interface(event);
    dev = snd_ctl_event_elem_get_device(event);
    subdev = snd_ctl_event_elem_get_subdevice(event);
    index = snd_ctl_event_elem_get_index(event);
    mask = snd_ctl_event_elem_get_mask(event);

    printf("\n%s event:\n", name);

    printf("  mask: 0x%08x (", mask);
    if (mask == SND_CTL_EVENT_MASK_REMOVE) {
        printf("remove");
    } else {
        i = 0;
        if (mask & SND_CTL_EVENT_MASK_VALUE)
            printf("%svalue", (i++ ? "," : ""));
        if (mask & SND_CTL_EVENT_MASK_INFO)
            printf("%sinfo", (i++ ? "," : ""));
        if (mask & SND_CTL_EVENT_MASK_ADD)
            printf("%sadd", (i++ ? "," : ""));
        if (mask & SND_CTL_EVENT_MASK_TLV)
            printf("%stlv", (i++ ? "," : ""));
    }
    printf(")\n");

    printf("  element:\n");
    printf("    numid: %u\n", numid);
    printf("    iface: %d (%s)\n", (int)intf, snd_ctl_elem_iface_name(intf));
    printf("    dev: %u\n", dev);
    printf("    subdev: %u\n", subdev);
    printf("    name: '%s'\n", snd_ctl_event_elem_get_name(event));
    printf("    index: %u\n", index);

    snd_ctl_elem_id_alloca(&id);
    snd_ctl_event_elem_get_id(event, id);

    snd_ctl_elem_info_alloca(&info);
    snd_ctl_elem_info_set_id(info, id);
    err = snd_ctl_elem_info(ctl, info);
    if (err < 0) return err;

    printf("  info:\n");

    printf("    access: ");
    {
        i = 0;
        if (snd_ctl_elem_info_is_readable(info))
            printf("%sread", (i++ ? "," : ""));
        if (snd_ctl_elem_info_is_writable(info))
            printf("%swrite", (i++ ? "," : ""));
        if (snd_ctl_elem_info_is_volatile(info))
            printf("%svolatile", (i++ ? "," : ""));
        if (snd_ctl_elem_info_is_inactive(info))
            printf("%sinactive", (i++ ? "," : ""));
        if (snd_ctl_elem_info_is_locked(info))
            printf("%slocked", (i++ ? "," : ""));
        if (snd_ctl_elem_info_is_owner(info))
            printf("%sowner; pid: %d", (i++ ? "," : ""),
                snd_ctl_elem_info_get_owner(info));
        if (snd_ctl_elem_info_is_user(info))
            printf("%suser", (i++ ? "," : ""));
    }
    putc('\n', stdout);

    if (mask != SND_CTL_EVENT_MASK_REMOVE && (mask & SND_CTL_EVENT_MASK_TLV))
    {
        bool tlv_r = snd_ctl_elem_info_is_tlv_readable(info);

        i = 0;
        printf("    tlv access:");
        if (tlv_r)
            printf("%sread", (i++ ? "," : ""));
        if (snd_ctl_elem_info_is_tlv_writable(info))
            printf("%swrite", (i++ ? "," : ""));
        if (snd_ctl_elem_info_is_tlv_commandable(info))
            printf("%scommand", (i++ ? "," : ""));
        putc('\n', stdout);

        if (tlv_r && snd_ctl_elem_tlv_read(ctl, id, tlv, sizeof(tlv)) >= 0) {
            printf("    tlv:\n");
            printf("      raw:\n");
            dump_hex_ints(tlv, tlv[1] / 4 + 2, "        ");

            if (snd_tlv_parse_dB_info(tlv, sizeof(tlv), &db_tlv) <= 0)
                db_tlv = NULL;
        }
    }

    count = snd_ctl_elem_info_get_count(info);
    printf("    count: %u\n", count);

    type = snd_ctl_elem_info_get_type(info);
    printf("    type: %d (%s)\n", type, snd_ctl_elem_type_name(type));

    switch (type)
    {
    case SND_CTL_ELEM_TYPE_INTEGER:
      {
        long step = snd_ctl_elem_info_get_step(info);

        int_min = snd_ctl_elem_info_get_min(info);
        int_max = snd_ctl_elem_info_get_max(info);
        printf("      min: %ld\n", int_min);
        printf("      max: %ld\n", int_max);
        if (step > 0)
            printf("      step: %ld\n", step);

        if (db_tlv) {
            long dbmin, dbmax;

            snd_tlv_get_dB_range(db_tlv, int_min, int_max, &dbmin, &dbmax);
            if (err >= 0) {
                printf("      dbmin: %ld\n", dbmin);
                printf("      dbmax: %ld\n", dbmax);
            } else
                db_tlv = NULL;
        }
        break;
      }

    case SND_CTL_ELEM_TYPE_INTEGER64:
      {
        long long step = snd_ctl_elem_info_get_step64(info);

        printf("      min: %lld\n", snd_ctl_elem_info_get_min64(info));
        printf("      max: %lld\n", snd_ctl_elem_info_get_max64(info));
        if (step > 0) printf("      step: %lld\n", step);
        break;
      }

    case SND_CTL_ELEM_TYPE_ENUMERATED:
      {
        const char *item_name;
        unsigned int items = snd_ctl_elem_info_get_items(info);

        for (i = 0; i < items; i++) {
            snd_ctl_elem_info_set_item(info, i);
            item_name = (snd_ctl_elem_info(ctl, info) < 0 ? "???" :
                snd_ctl_elem_info_get_item_name(info));
            printf("      %d: '%s'\n", i, item_name);
        }
        break;
      }

    default:
        break;
    }

    if (type == SND_CTL_ELEM_TYPE_NONE || !count)
        return 0;

    snd_ctl_elem_value_alloca(&val);
    snd_ctl_elem_value_set_id(val, id);
    err = snd_ctl_elem_read(ctl, val);
    if (err < 0) return err;

    switch (type)
    {
    case SND_CTL_ELEM_TYPE_BOOLEAN:
        printf("  bool(s):\n");
        for (i = 0; i < count; i++) {
            printf("    %s\n",
                snd_ctl_elem_value_get_boolean(val, i) ? "true" : "false");
        }
        break;

    case SND_CTL_ELEM_TYPE_INTEGER:
        printf("  int(s):\n");
        for (i = 0; i < count; i++) {
            long v = snd_ctl_elem_value_get_integer(val, i);
            printf("    %ld", v);
            if (db_tlv) {
                long db_gain;
                if (snd_tlv_convert_to_dB(
                        db_tlv, int_min, int_min, v, &db_gain) >= 0)
                    printf("; dB gain: %ld", db_gain);
            }
            putc('\n', stdout);
        }
        break;

    case SND_CTL_ELEM_TYPE_INTEGER64:
        printf("  int64(s):\n");
        for (i = 0; i < count; i++) {
            printf("    %lld\n", snd_ctl_elem_value_get_integer64(val, i));
        }
        break;

    case SND_CTL_ELEM_TYPE_ENUMERATED:
        printf("  enum:\n");
        break;

    case SND_CTL_ELEM_TYPE_BYTES:
        printf("  byte(s):\n");
        dump_hex_bytes((const unsigned char*)snd_ctl_elem_value_get_bytes(val),
            count, "    ");
        break;

    case SND_CTL_ELEM_TYPE_IEC958:
      {
          snd_aes_iec958_t iec958;
          snd_ctl_elem_value_get_iec958(val, &iec958);

          printf("  iec958:\n");
          printf("    status:\n");
          dump_hex_bytes((const unsigned char*)&iec958.status,
              sizeof(iec958.status), "      ");
          printf("    subcode:\n");
          dump_hex_bytes((const unsigned char*)&iec958.subcode,
              sizeof(iec958.subcode), "      ");
          printf("    pad:\n");
          dump_hex_bytes((const unsigned char*)&iec958.pad,
              sizeof(iec958.pad), "      ");
          printf("    dig_subframe:\n");
          dump_hex_bytes((const unsigned char*)&iec958.dig_subframe,
              sizeof(iec958.dig_subframe), "      ");

          break;
      }

    default:
        printf("  ???\n");
    }

    return 0;
}

static int operate_dispatcher(int epfd, uint32_t op, struct epoll_event *epev,
    struct src_entry *entry)
{
    struct pollfd *pfds = NULL;
    int count;
    int i;
    int err = 0;

    pfds = calloc(entry->pfd_count, sizeof(*pfds));
    if (!pfds) {
        err = -ENOMEM;
        goto end;
    }

    count = snd_ctl_poll_descriptors(entry->handle, pfds, entry->pfd_count);
    if (count < 0) {
        err = count;
        goto end;
    }

    if (count != entry->pfd_count) {
        err = -EIO;
        goto end;
    }

    for (i = 0; i < entry->pfd_count; ++i) {
        err = epoll_ctl(epfd, op, pfds[i].fd, epev);
        if (err < 0)
            break;
    }
end:
    if (pfds) free(pfds);
    return err;
}

static int prepare_dispatcher(int epfd, int sigfd, int infd,
    struct list_head *srcs)
{
    struct epoll_event ev = {0};
    struct src_entry *entry;
    int err = 0;

    ev.events = EPOLLIN;
    ev.data.fd = sigfd;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, sigfd, &ev) < 0)
        return -errno;

    ev.events = EPOLLIN;
    ev.data.fd = infd;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, infd, &ev) < 0)
        return -errno;

    list_for_each_entry(entry, srcs, list) {
        ev.events = EPOLLIN;
        ev.data.ptr = (void *)entry;
        err = operate_dispatcher(epfd, EPOLL_CTL_ADD, &ev, entry);
        if (err < 0)
            break;
    }

    return err;
}

static int run_dispatcher(int epfd, int sigfd, int infd, struct list_head *srcs,
    bool *retry)
{
    struct src_entry *entry;
    unsigned int max_ev_count;
    struct epoll_event *epev;
    int err = 0;

    max_ev_count = 0;
    list_for_each_entry(entry, srcs, list)
        max_ev_count += entry->pfd_count;

    epev = calloc(max_ev_count, sizeof(*epev));
    if (!epev)
        return -ENOMEM;

    while (true) {
        int count;
        int i;

        count = epoll_wait(epfd, epev, max_ev_count, -1);
        if (count < 0) {
            if (errno == EINTR)
                continue;
            err = count;
            break;
        }
        if (count == 0)
            continue;

        for (i = 0; i < count; ++i) {
            struct epoll_event *ev = epev + i;

            if (ev->data.fd == sigfd)
                goto end;

            if (ev->data.fd == infd) {
                err = check_control_cdev(infd, retry);
                if (err < 0 || *retry)
                    goto end;
                continue;
            }

            entry = ev->data.ptr;
            if (ev->events & EPOLLIN)
                print_event(entry->handle, entry->name);
            if (ev->events & EPOLLERR) {
                operate_dispatcher(epfd, EPOLL_CTL_DEL, NULL, entry);
                remove_source_entry(entry);
            }
        }
    }
end:
    free(epev);
    return err;
}

static void clear_dispatcher(int epfd, int sigfd, int infd,
    struct list_head *srcs)
{
    struct src_entry *entry;

    list_for_each_entry(entry, srcs, list)
        operate_dispatcher(epfd, EPOLL_CTL_DEL, NULL, entry);

    epoll_ctl(epfd, EPOLL_CTL_DEL, infd, NULL);

    epoll_ctl(epfd, EPOLL_CTL_DEL, sigfd, NULL);
}

static int prepare_signalfd(int *sigfd)
{
    sigset_t mask;
    int fd;

    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTERM);

    if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0)
        return -errno;

    fd = signalfd(-1, &mask, 0);
    if (fd < 0)
        return -errno;
    *sigfd = fd;

    return 0;
}

int main(int argc, char *argv[])
{
    const char *name = NULL;
    LIST_HEAD(srcs);
    int sigfd = -1;
    int epfd = -1;
    int infd = -1;
    int wd = -1;
    bool retry;
    int err = 0;

    if (argc <= 1)
        name = NULL;
    else if (argc == 2)
        name = argv[1];
    else {
        fprintf(stderr, "Usage: %s [card_name]\n", argv[0]);
        return -EINVAL;
    }

    err = prepare_signalfd(&sigfd);
    if (err < 0)
        goto end;

    epfd = epoll_create(1);
    if (epfd < 0) {
        err = -errno;
        goto end;
    }

    infd = inotify_init1(IN_NONBLOCK);
    if (infd < 0) {
        err = -errno;
        goto end;
    }

    wd = inotify_add_watch(infd, "/dev/snd/", IN_CREATE);
    if (wd < 0) {
        err = -errno;
        goto end;
    }

retry:
    retry = false;

    err = prepare_source_entry(&srcs, name);
    if (err < 0)
        goto end;

    err = prepare_dispatcher(epfd, sigfd, infd, &srcs);
    if (err >= 0)
        err = run_dispatcher(epfd, sigfd, infd, &srcs, &retry);

    clear_dispatcher(epfd, sigfd, infd, &srcs);

    if (retry) {
        // A simple makeshift for timing gap between creation of nodes
        // by devtmpfs and chmod() by udevd.
        struct timespec req = { .tv_sec = 1 };
        nanosleep(&req, NULL);
        goto retry;
    }

end:
    if (wd >= 0) inotify_rm_watch(infd, wd);
    if (infd >= 0) close(infd);
    if (epfd >= 0) close(epfd);
    if (sigfd >= 0) close(sigfd);
    clear_source_list(&srcs);

    return err;
}
