package com.cheatguard.security;

import com.cheatguard.config.AppPaths;

import java.io.File;
import java.io.RandomAccessFile;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;

/** Prevents two Cheat.Guard processes from running at the same time. */
public final class InstanceGuard {
    private RandomAccessFile raf;
    private FileChannel channel;
    private FileLock lock;

    public boolean acquire() {
        try {
            File f = new File(AppPaths.getDataDirectory(), "instance.lock");
            raf = new RandomAccessFile(f, "rw");
            channel = raf.getChannel();
            lock = channel.tryLock();
            if (lock == null) {
                close();
                return false;
            }
            return true;
        } catch (Exception e) {
            close();
            return false;
        }
    }

    public void close() {
        try { if (lock != null && lock.isValid()) lock.release(); } catch (Exception ignored) {}
        try { if (channel != null && channel.isOpen()) channel.close(); } catch (Exception ignored) {}
        try { if (raf != null) raf.close(); } catch (Exception ignored) {}
        lock = null; channel = null; raf = null;
    }
}
