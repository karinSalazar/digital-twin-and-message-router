# Utiliza una imagen de Python como base
FROM python:3.9-slim

# Establece el directorio de trabajo en /app
WORKDIR /app
# Copiamos el archivo de variables de entorno
#COPY .env_vars /app/.env_vars
# Copiamos el paquete
COPY tbmq-main /app/tbmq-main
# Copia el código fuente al contenedor
COPY code /app/code

COPY code/requirements.txt .

RUN pip install --no-cache-dir -r code/requirements.txt


# asegurarnos de que la salida de nuestro script Python no esté almacenada en el búfer
ENV PYTHONUNBUFFERED=1

# Ejecuta el script cuando se inicie el contenedor
CMD ["python", "code/vehicleDigitalTwin.py"]
