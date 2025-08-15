FROM python:3.10.13-slim

WORKDIR /app

# Copy requirements and install dependencies
COPY requirements_render.txt .
RUN pip install --no-cache-dir -r requirements_render.txt

# Copy application files
COPY . .

# Expose port
EXPOSE 8501

# Set environment variables
ENV STREAMLIT_SERVER_PORT=8501
ENV STREAMLIT_SERVER_ADDRESS=0.0.0.0

# Run the application
CMD ["streamlit", "run", "render_app.py", "--server.port", "8501", "--server.address", "0.0.0.0"]
