FROM eclipse-temurin:8-jdk-alpine
WORKDIR /app
COPY . .
RUN apk add --no-cache curl && \
    curl -sL -o log4j-core.jar https://repo1.maven.org/maven2/org/apache/logging/log4j/log4j-core/2.14.1/log4j-core-2.14.1.jar && \
    curl -sL -o log4j-api.jar https://repo1.maven.org/maven2/org/apache/logging/log4j/log4j-api/2.14.1/log4j-api-2.14.1.jar && \
    javac -cp "log4j-core.jar:log4j-api.jar" Server.java
EXPOSE 8080
CMD ["java", "-Dlog4j2.formatMsgNoLookups=false", "-Dcom.sun.jndi.ldap.object.trustURLCodebase=true", "-cp", ".:log4j-core.jar:log4j-api.jar", "Server"]
