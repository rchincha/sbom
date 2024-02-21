package fs

import (
	"sync"
)

type ThreadPool interface {
	// Add adds a task for the threadpool to consume
	Add(taskfn func() error)

	// Done finishes the threadpool
	Done() error
}

type threadpool struct {
	wg      sync.WaitGroup
	n       int
	backlog int
	tasks   chan func() error
	err     error
}

func NewThreadPool(n, backlog int) *threadpool {
	pool := &threadpool{n: n, backlog: backlog, tasks: make(chan func() error, backlog)}

	for i := 0; i < n; i++ {
		// start the runners
		pool.wg.Add(1)
		go pool.runner()
	}

	return pool
}

func (pool *threadpool) Add(f func() error) {
	pool.tasks <- f
}

func (pool *threadpool) runner() {
	defer pool.wg.Done()

	for {
		taskfn, ok := <-pool.tasks
		if !ok {
			// no more tasks
			return
		}

		// ignore failures, save error
		if err := taskfn(); err != nil {
			pool.err = err
		}
	}
}

func (pool *threadpool) Done() error {
	close(pool.tasks)
	pool.wg.Wait()

	return pool.err
}
