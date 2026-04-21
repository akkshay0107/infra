FROM python:3.13-slim
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN pip install uv
RUN uv sync
COPY . .
ENV PYTHONUNBUFFERED=1
ENV SHOWDOWN_WS_URL=ws://ps-server:8000/showdown/websocket
ENV SHOWDOWN_AUTH_URL=http://login:3001/api/action.php?
ENV SHOWDOWN_USERNAME=Bot
CMD ["uv", "run", "src/rl_player.py"]
