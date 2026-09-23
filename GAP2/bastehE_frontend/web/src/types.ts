// Types for the web application
// Based on the architecture v2.0 specification

import type { User as AuthUser } from '../types'

/** User type from authentication */
export interface User {
  id: string
  username: string
  display_name: string
  national_id_masked: string  // ******1234 format
  is_active: boolean
  roles: string[]
  permissions: string[]
  privacy_level: 'fully_private' | 'team_only' | 'selected' | 'fully_transparent'
  auth_mode: 'local' | 'sso' | 'both'
  mfa_enabled: boolean
  last_login_at: string | null
  theme: 'light' | 'dark'
  locale: 'fa-IR' | 'en'
  timezone: string
}

/** Login credentials */
export interface LoginCredentials {
  identifier: string  // username or national ID
  password: string
  rememberMe?: boolean
}

/** Registration credentials */
export interface RegisterCredentials {
  nationalId: string
  username: string
  password: string
  displayName: string
  email?: string
  mobile?: string
}

/** API response types */
export interface ApiResponse<T> {
  data: T
  success: boolean
  message: string
  error?: string
  request_id: string
}

/** Paginated response */
export interface PaginatedResponse<T> {
  data: T[]
  total: number
  page: number
  page_size: number
  total_pages: number
}

/** Dashboard widget types */
export interface WidgetConfig {
  block_key: string
  position_x: number
  position_y: number
  width: number
  height: number
  is_visible: boolean
  config: Record<string, any>
  style?: Record<string, any>
}

/** Goal types */
export interface Goal {
  id: string
  title: string
  description?: string
  owner_id: string
  privacy_level: GoalPrivacyLevel
  progress_pct: number
  status: GoalStatus
  start_date?: string
  due_date?: string
  created_at: string
  updated_at: string
  tags: string[]
}

export type GoalPrivacyLevel = 'fully_private' | 'team_only' | 'selected' | 'fully_transparent'
export type GoalStatus = 'active' | 'completed' | 'archived'

/** Task types */
export interface Task {
  id: string
  goal_id: string
  title: string
  description?: string
  assignee_id?: string
  owner_id: string
  privacy_level: GoalPrivacyLevel
  status: TaskStatus
  priority: 'normal' | 'high' | 'low'
  progress_pct: number
  due_date?: string
  created_at: string
}

export type TaskStatus = 'pending' | 'in_progress' | 'completed' | 'deferred'

/** Tag types */
export interface Tag {
  id: string
  name: string
  color: string
  created_at: string
}

/** Dashboard types */
export interface DashboardData {
  goal: Goal
  owner: User
  tasks: Task[]
  privacy_applied: boolean
  redaction: 'full' | 'aggregate_only' | 'hidden'
}

/** Quick action types */
export type QuickAction =
  | 'dashboard'
  | 'goals'
  | 'calendar'
  | 'inbox'
  | 'reports'
  | 'widgets'
  | 'profile'

/** Chat types */
export interface ChatMessage {
  id: string
  room_id: string
  sender_id: string
  body: string
  sender_name: string
  created_at: string
  message_type: 'text' | 'file' | 'system'
  edited: boolean
}

export interface ChatRoom {
  id: string
  title: string
  linked_type?: 'task' | 'meeting' | 'goal' | null
  linked_id?: string
  owner_id: string
  is_archived: boolean
  member_count: number
}

/** Inbox types */
export interface InboxItem {
  id: string
  sender_id: string
  recipient_id: string
  item_type: 'meeting_invite' | 'share_request' | 'task_assignment' | 'chat_invite' | 'approval'
  entity_type?: string
  entity_id?: string
  title: string
  message?: string
  priority: 'normal' | 'high' | 'low'
  action_state: 'pending' | 'accepted' | 'rejected' | 'deferred' | 'expired'
  receipt_state: 'sent' | 'seen' | 'acted'
  seen_at?: string
  acted_at?: string
  defer_until?: string
  response_note?: string
  due_at?: string
  expires_at?: string
  created_at: string
}

export interface OutboxItem {
  id: string
  recipient_id: string
  title: string
  message?: string
  created_at: string
  read_receipt: boolean
}

/** Privacy exception types */
export interface PrivacyException {
  id: string
  owner_id: string
  viewer_id: string
  entity_type?: string
  can_comment: boolean
  granted_at: string
  expires_at?: string
}

/** API error types */
export interface ApiError {
  error_code: string
  message: string
  details?: any
  status_code: number
}

/** Router types */
export interface RoutePath {
  path: string
  element: React.ReactNode
  exact?: boolean
  index?: boolean
}

/** Export all types */
export type {
  User,
  LoginCredentials,
  RegisterCredentials,
  ApiResponse,
  PaginatedResponse,
  Goal,
  GoalPrivacyLevel,
  GoalStatus,
  Task,
  TaskStatus,
  Tag,
  DashboardData,
  QuickAction,
  ChatMessage,
  ChatRoom,
  InboxItem,
  OutboxItem,
  PrivacyException,
  ApiError,
  RoutePath,
  WidgetConfig
}