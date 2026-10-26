FROM maven:3.9-eclipse-temurin-17 AS build
WORKDIR /app
COPY pom.xml .
COPY src ./src
RUN mvn -B package

FROM eclipse-temurin:17-jre
WORKDIR /app
COPY --from=build /app/target ./target
COPY . .
ENV PORT=10000
CMD ["sh", "-c", "java -jar target/logiqual-qms-1.0.0.jar"]