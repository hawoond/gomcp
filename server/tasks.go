package server

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/hawoond/gomcp/internal/types"
)

func (s *Server) startToolTask(requestContext context.Context, tool Tool, arguments map[string]interface{}, requestedTTL int64) (*types.Task, error) {
	now := time.Now().UTC()

	s.tasksMu.Lock()
	s.pruneExpiredTasksLocked(now)
	if len(s.tasks) >= s.maxTasks {
		s.tasksMu.Unlock()
		return nil, fmt.Errorf("task capacity reached")
	}
	ttl := s.taskTTL
	if requestedTTL > 0 {
		requested := time.Duration(requestedTTL) * time.Millisecond
		if requested < ttl {
			ttl = requested
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	timestamp := now.Format(time.RFC3339Nano)
	task := &types.Task{
		ID:            uuid.NewString(),
		Status:        types.TaskStatusWorking,
		CreatedAt:     timestamp,
		LastUpdatedAt: timestamp,
		TTL:           ttl.Milliseconds(),
		PollInterval:  250,
	}
	s.tasks[task.ID] = task
	s.taskCancels[task.ID] = cancel
	s.taskExpires[task.ID] = now.Add(ttl)
	s.taskSessions[task.ID] = sessionIDFromContext(requestContext)
	s.taskNotifiers[task.ID] = notificationSenderFromContext(requestContext)
	taskCopy := *task
	s.tasksMu.Unlock()

	s.publishTaskStatus(task.ID, taskCopy)
	go s.runToolTask(ctx, task.ID, tool, arguments)
	return &taskCopy, nil
}

func (s *Server) runToolTask(ctx context.Context, taskID string, tool Tool, arguments map[string]interface{}) {
	result, err := s.invokeTool(ctx, tool, arguments)
	toolResult := toToolResult(result, err)
	toolResult.Meta = map[string]interface{}{
		"io.modelcontextprotocol/related-task": map[string]interface{}{"taskId": taskID},
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)

	s.tasksMu.Lock()
	task, ok := s.tasks[taskID]
	if !ok || task.Status == types.TaskStatusCancelled {
		s.tasksMu.Unlock()
		return
	}
	if toolResult.IsError {
		task.Status = types.TaskStatusFailed
		if len(toolResult.Content) > 0 {
			task.StatusMessage = toolResult.Content[0].Text
		}
	} else {
		task.Status = types.TaskStatusCompleted
	}
	task.LastUpdatedAt = now
	s.taskResults[taskID] = toolResult
	delete(s.taskCancels, taskID)
	taskCopy := *task
	s.tasksMu.Unlock()

	s.publishTaskStatus(task.ID, taskCopy)
}

func (s *Server) getTask(ctx context.Context, taskID string) (*types.Task, error) {
	now := time.Now().UTC()
	s.tasksMu.Lock()
	defer s.tasksMu.Unlock()
	s.pruneExpiredTasksLocked(now)
	task, ok := s.tasks[taskID]
	if !ok || s.taskSessions[taskID] != sessionIDFromContext(ctx) {
		return nil, fmt.Errorf("task not found")
	}
	taskCopy := *task
	return &taskCopy, nil
}

func (s *Server) getTaskResult(ctx context.Context, taskID string) (interface{}, error) {
	now := time.Now().UTC()
	s.tasksMu.Lock()
	defer s.tasksMu.Unlock()
	s.pruneExpiredTasksLocked(now)
	task, ok := s.tasks[taskID]
	if !ok || s.taskSessions[taskID] != sessionIDFromContext(ctx) {
		return nil, fmt.Errorf("task not found")
	}
	if task.Status == types.TaskStatusWorking || task.Status == types.TaskStatusInputRequired {
		return nil, fmt.Errorf("task result is not ready")
	}
	result, ok := s.taskResults[taskID]
	if !ok {
		if task.Status == types.TaskStatusCancelled {
			return types.ErrorResult(fmt.Errorf("task cancelled")), nil
		}
		return nil, fmt.Errorf("task result is unavailable")
	}
	return result, nil
}

func (s *Server) cancelTask(ctx context.Context, taskID string) (*types.Task, error) {
	s.tasksMu.Lock()
	task, ok := s.tasks[taskID]
	if !ok || s.taskSessions[taskID] != sessionIDFromContext(ctx) {
		s.tasksMu.Unlock()
		return nil, fmt.Errorf("task not found")
	}
	if task.Status == types.TaskStatusCompleted || task.Status == types.TaskStatusFailed || task.Status == types.TaskStatusCancelled {
		taskCopy := *task
		s.tasksMu.Unlock()
		return &taskCopy, nil
	}
	if cancel := s.taskCancels[taskID]; cancel != nil {
		cancel()
	}
	task.Status = types.TaskStatusCancelled
	task.StatusMessage = "Cancelled by requestor"
	task.LastUpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	delete(s.taskCancels, taskID)
	taskCopy := *task
	s.tasksMu.Unlock()

	s.publishTaskStatus(task.ID, taskCopy)
	return &taskCopy, nil
}

func (s *Server) listTasks(ctx context.Context, cursor string) ([]types.Task, string, error) {
	now := time.Now().UTC()
	s.tasksMu.Lock()
	s.pruneExpiredTasksLocked(now)

	ids := make([]string, 0, len(s.tasks))
	for taskID := range s.tasks {
		if s.taskSessions[taskID] == sessionIDFromContext(ctx) {
			ids = append(ids, taskID)
		}
	}
	sort.Strings(ids)
	tasks := make([]types.Task, 0, len(ids))
	for _, taskID := range ids {
		tasks = append(tasks, *s.tasks[taskID])
	}
	s.tasksMu.Unlock()
	s.rwMu.RLock()
	pageSize := s.pageSize
	s.rwMu.RUnlock()
	return paginate(tasks, cursor, pageSize)
}

func (s *Server) pruneExpiredTasksLocked(now time.Time) {
	for taskID, expiresAt := range s.taskExpires {
		if now.Before(expiresAt) {
			continue
		}
		if cancel := s.taskCancels[taskID]; cancel != nil {
			cancel()
		}
		delete(s.tasks, taskID)
		delete(s.taskResults, taskID)
		delete(s.taskCancels, taskID)
		delete(s.taskExpires, taskID)
		delete(s.taskSessions, taskID)
		delete(s.taskNotifiers, taskID)
	}
}

func (s *Server) publishTaskStatus(taskID string, task types.Task) {
	s.tasksMu.RLock()
	sessionID := s.taskSessions[taskID]
	notifier := s.taskNotifiers[taskID]
	s.tasksMu.RUnlock()
	if notifier != nil {
		_ = notifier("notifications/tasks/status", task)
		return
	}
	if sessionID == "" {
		return
	}
	if session, ok := s.session(sessionID); ok {
		s.publishToSession(session, "notifications/tasks/status", task)
	}
}
