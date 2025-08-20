// src/constants/api.ts
// Centralized API endpoints. Default should be production (.com)
export const API_ENDPOINTS = {
	prod: "https://api.klaay.com",
	dev: "https://api.klaay.dev",
} as const;

export type ApiEnv = keyof typeof API_ENDPOINTS;

// Back-compat default URL (production)
export const DEFAULT_API_BASE_URL = API_ENDPOINTS.prod;
