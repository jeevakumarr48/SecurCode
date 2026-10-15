# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Stack

React + Vite, delegated for a lightweight frontend with a production build.

## Users

Security engineers operating code scans during local or team development work.

## Product Purpose

SecurCode scans software projects for security issues and gives engineers a focused place to review scan status, findings, and history. Success means an engineer can start a scan, understand its result, and inspect findings without leaving the console.

## Positioning

The product combines a local project scan workflow with persistent scan history and aggregated finding statistics through a small REST API.

## Operating Context

Engineers work from a desktop or laptop while evaluating project directories inside the backend workspace. The overview is a frequent operational surface; scan launch and finding inspection are the primary tasks.

## Capabilities and Constraints

- The frontend consumes GET `/status`, GET `/stats`, GET `/history`, and POST `/scan`.
- The API accepts relative project paths inside its workspace.
- API base URL is configurable with `VITE_API_BASE_URL` and defaults to `http://127.0.0.1:8000`.
- The interface must use API data and must not fabricate metrics, findings, or scan history.
- Existing endpoint paths and response fields remain backward-compatible; scanner output adds the `language` field for new findings.

## Brand Commitments

The product name is SecurCode. The interface should feel like an original, professional cloud security console and may use a simple original shield mark without copying third-party branding.

## Evidence on Hand

The backend API and SQLite-backed scan history are the available product evidence. No customer, benchmark, pricing, or marketing claims are available and must not be invented.

## Product Principles

- Make current security state immediately legible.
- Keep scan launch and recovery from errors direct and practical.
- Prefer precise, dense evidence over decorative visualization.
- Preserve trust by distinguishing live API state from loading, empty, and failed states.
