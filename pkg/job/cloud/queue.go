package cloud

import (
	"context"
	"sync"

	"github.com/accuknox/omniscan/pkg/job"
)

type queue struct {
	block   chan struct{}
	wg      *sync.WaitGroup
	summary summary
}

func newQueue(concurrency uint) queue {
	return queue{
		block:   make(chan struct{}, concurrency),
		wg:      new(sync.WaitGroup),
		summary: newSummary(),
	}
}

func (q *queue) dequeue() {
	<-q.block
	q.wg.Done()
}

func (q *queue) Enqueue(ctx context.Context, fn func() (string, *job.ErrorSummary)) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case q.block <- struct{}{}:
		q.wg.Add(1)
		go func() {
			uri, errors := fn()
			if errors != nil {
				q.summary.Write(uri, *errors)
			}
			q.dequeue()
		}()
	}

	return nil
}

func (q *queue) Wait() job.ErrorSummaryMap {
	q.wg.Wait()
	return q.summary.Read()
}
