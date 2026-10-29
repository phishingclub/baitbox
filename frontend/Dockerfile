# development docker file for the Bait Box admin SPA (vite dev server)
FROM node:22-slim@sha256:6c74791e557ce11fc957704f6d4fe134a7bc8d6f5ca4403205b2966bd488f6b3

WORKDIR /app
RUN chown -R node:node /app
USER node
CMD [ "bash", "/app/dev.sh" ]
