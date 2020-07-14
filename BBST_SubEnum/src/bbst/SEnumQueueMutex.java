/**
 * $Project (c) Bug Busters Security Team 2020
 */
package bbst;

import java.util.concurrent.atomic.AtomicBoolean;

public class SEnumQueueMutex {
    private AtomicBoolean lock;
    private Object mutex;

    public SEnumQueueMutex(boolean locked) {
        lock = new AtomicBoolean(locked);
        mutex = new Object();
    }

    public void step() throws InterruptedException
    {
        if (lock.get()) synchronized(mutex) {
            mutex.wait();
        }
    }
    public void pause() {
        lock.set(true);
    }

    public void resume() {
        lock.set(false);

        synchronized(mutex) {
            mutex.notify();
        }
    }
}