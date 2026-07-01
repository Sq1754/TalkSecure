FROM node:20

# Create app directory
WORKDIR /app

# Install app dependencies
COPY package*.json ./
RUN npm ci --omit=dev

# Bundle app source
COPY . .

# Expose server port
EXPOSE 3000

# Set environment variables for production execution
ENV NODE_ENV=production
ENV PORT=3000
ENV HOST=0.0.0.0
ENV DB_PATH=/app/data/vault.db
ENV UPLOADS_PATH=/app/data/uploads

# Run startup command
CMD ["node", "server/index.js"]
