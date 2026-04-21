This repository contains the infrastructure configuration for the Pokemon VGC Research Environment, including a local battle server, a custom login server, and a Caddy reverse proxy.

## Overview

- **ps-server**: A customized Pokemon Showdown server.
- **login**: A lightweight Express/LiteSQL server for handling user authentication and session assertions.
- **bot**: A reinforcement learning bot container.
- **caddy**: Reverse proxy for serving the client and routing traffic to the internal services.

## Directory Structure

```text
.
├── Caddyfile
├── docker
│   ├── bot/
│   └── server/
├── docker-compose.yml
├── login-server/
│   ├── Dockerfile
│   ├── generate-keys.js
│   ├── generate-users.js
│   ├── index.js
│   └── package.json
└── README.md
```

## Prerequisites

This repository is designed to run within a specific directory structure. You must have the following sibling repositories cloned to your machine:

```text
.
├── infra/           # (This repository)
├── vgc-rl/          # RL Player & Showdown Server source
└── client/          # Pokemon Showdown client build
```

Additionally you need **Docker** and **Docker Compose** installed.

## Setup

1. **Env Variables**:
   Copy `.env.example` to `.env` and fill in your credentials:
   ```bash
   cp .env.example .env
   ```

2. **Generate Keys & Users**:
   Before starting the servers for the first time, you need to generate RSA keys for the login server and initialize the user database:
   ```bash
   cd login-server
   npm install
   node generate-keys.js
   node --env-file=../.env generate-users.js
   ```
   Hacky way right now to support around 250 participants. Will resolve this to a proper auth system with user creation later.

3. **Launch**:
   ```bash
   docker-compose up --build
   ```
