FROM eclipse-temurin:21-jdk-alpine AS build
WORKDIR /app
COPY build.gradle settings.gradle ./
COPY src src
RUN apk add --no-cache bash && \
    wget -q https://services.gradle.org/distributions/gradle-8.5-bin.zip -O gradle.zip && \
    unzip -q gradle.zip && \
    ./gradle-8.5/bin/gradle --no-daemon shadowJar

FROM eclipse-temurin:21-jre-alpine
WORKDIR /app
COPY --from=build /app/build/libs/*-all.jar app.jar
EXPOSE 8080
CMD ["java", "-jar", "app.jar"]
