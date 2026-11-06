import { randomUUID } from 'node:crypto';

export type ActivityCategory = 'repository' | 'security' | 'investigation' | 'patch' | 'verification' | 'dependencies';
export type ActivityStatus = 'success' | 'warning' | 'error' | 'info';
export type ActivityEvent = {
  id: string;
  occurredAt: string;
  category: ActivityCategory;
  status: ActivityStatus;
  title: string;
  details: string;
  repository: string | null;
};

const MAX_ACTIVITY_EVENTS = 500;

export class ActivityLog {
  private readonly events: ActivityEvent[] = [];

  record(input: Omit<ActivityEvent, 'id' | 'occurredAt'>): ActivityEvent {
    const event: ActivityEvent = {
      id: randomUUID(), occurredAt: new Date().toISOString(), ...input,
      title: input.title.slice(0,160), details: input.details.slice(0,2000),
      repository: input.repository?.slice(0,160) ?? null,
    };
    this.events.unshift(event);
    if (this.events.length > MAX_ACTIVITY_EVENTS) this.events.length = MAX_ACTIVITY_EVENTS;
    return event;
  }

  list(limit = 200): ActivityEvent[] {
    return this.events.slice(0, Math.max(1, Math.min(MAX_ACTIVITY_EVENTS, Math.trunc(limit) || 200)));
  }
}
