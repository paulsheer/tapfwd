
#define errno_TEMP()            (errno == EWOULDBLOCK || errno == EAGAIN || errno == EINTR || errno == EINPROGRESS)

static int WARN_UNUSED readwriteall (const int one_for_write, const int sock, void *const buf_, const int len_, const int timeout, char * const errmsg)
{
    unsigned char *buf;
    int tot = 0, len = len_;
    buf = (unsigned char *) buf_;

    time_t t1, t2;
    time (&t1);

    *errmsg = '\0';

    while (len > 0) {
        int c;
        if (one_for_write)
            c = write (sock, buf, len);
        else
            c = read (sock, buf, len);
        if (c > 0) {
            tot += c;
            buf += c;
            len -= c;
            continue;
        }
        if (c < 0 && errno_TEMP ()) {
            struct timeval tv;
            int sr;
            fd_set the_fdset;

          select_again:
            time (&t2);
            if (t2 - t1 > timeout) {
                snprintf (errmsg, ERRMSG_LEN, "timeout waiting for %s", one_for_write ? "write" : "read");
                return -1;
            }

            tv.tv_sec = 1;
            tv.tv_usec = 0;
            FD_ZERO (&the_fdset);
            FD_SET (sock, &the_fdset);
            if (one_for_write)
                sr = select (sock + 1, NULL, &the_fdset, NULL, &tv);
            else
                sr = select (sock + 1, &the_fdset, NULL, NULL, &tv);
            if (sr > 0)
                continue;
            if (sr < 0 && errno_TEMP ())
                goto select_again;
            if (sr == 0)
                goto select_again;
            if (sr < 0) {
                snprintf (errmsg, ERRMSG_LEN, "file descriptor error: %s", strerror (errno));
                return -1;
            }
        } else if (c == 0) {
            strcpy (errmsg, "remote closed connection");
            return -1;
        } else {
            snprintf (errmsg, ERRMSG_LEN, "socket error: %s", strerror (errno));
            return -1;
        }
    }
    return tot;
}

static int WARN_UNUSED writeall (int sock, void *buf, int len, char *errmsg)
{
    return readwriteall (1, sock, buf, len, 5, errmsg);
}

static int WARN_UNUSED readall (int sock, void *buf, int len, char *errmsg)
{
    return readwriteall (0, sock, buf, len, 20, errmsg);
}
