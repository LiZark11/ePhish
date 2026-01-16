FROM node:18-alpine

WORKDIR /app
COPY package*.json ./
RUN npm install

# Install Tailwind CSS and related packages
RUN npm install -D tailwindcss postcss autoprefixer
RUN npx tailwindcss init -p

COPY . .

EXPOSE 3000

CMD ["npm", "start"]