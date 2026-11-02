# Shield on Hugging Face Spaces (free CPU Basic). Also works on any Docker host.
FROM python:3.12-slim

# Spaces run the container as user 1000
RUN useradd -m -u 1000 user
USER user
ENV HOME=/home/user \
    PATH=/home/user/.local/bin:$PATH \
    PYTHONUNBUFFERED=1
WORKDIR $HOME/app

COPY --chown=user requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

COPY --chown=user . .
# Download the top-sites lists the model uses, then train during the build
# (20-45 minutes, needs about 4 GB RAM), so the app starts ready
RUN python backend/scripts/download_data.py && python ml/train_baseline.py

EXPOSE 7860
CMD ["python", "-m", "uvicorn", "space_app:app", "--host", "0.0.0.0", "--port", "7860", "--proxy-headers", "--forwarded-allow-ips", "*"]
