import { apiGet, apiPost } from "./client";
import type { RemoteSubmissionStatus } from "./types";

export function getRemoteSubmission(): Promise<RemoteSubmissionStatus> {
  return apiGet<RemoteSubmissionStatus>("/remote-submission");
}

export function enableRemoteSubmission(): Promise<RemoteSubmissionStatus> {
  return apiPost<RemoteSubmissionStatus>("/remote-submission/enable");
}

export function disableRemoteSubmission(): Promise<RemoteSubmissionStatus> {
  return apiPost<RemoteSubmissionStatus>("/remote-submission/disable");
}

export function rotateRemoteSubmission(): Promise<RemoteSubmissionStatus> {
  return apiPost<RemoteSubmissionStatus>("/remote-submission/rotate");
}
