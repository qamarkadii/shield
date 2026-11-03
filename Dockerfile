# Shield on Hugging Face Spaces (free CPU Basic). Also works on any Docker host.
FROM python:3.12-slim

# System libraries for the headless browser used by the page check (backend/app/pagecheck.py)
RUN pip install --no-cache-dir playwright==1.64.1 && python -m playwright install-deps chromium

# Spaces run the container as user 1000
RUN useradd -m -u 1000 user
USER user
ENV HOME=/home/user \
    PATH=/home/user/.local/bin:$PATH \
    PYTHONUNBUFFERED=1
WORKDIR $HOME/app

COPY --chown=user requirements.txt requirements-lock.txt ./
RUN pip install --no-cache-dir --user -r requirements-lock.txt && python -m playwright install chromium

COPY --chown=user . .
# Preserve packaged models/checkpoints and their matching data snapshots.
# Train only if no recoverable model exists; partial runs resume rather than reset.
RUN python tools/ensure_model.py --train-if-missing

EXPOSE 7860
CMD ["python", "-m", "uvicorn", "space_app:app", "--host", "0.0.0.0", "--port", "7860", "--proxy-headers", "--forwarded-allow-ips", "*"]
