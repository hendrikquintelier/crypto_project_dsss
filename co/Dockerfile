# Use Eclipse Temurin JDK 17
FROM eclipse-temurin:21-jdk

# Install Maven for building the project
RUN apt-get update && \
    apt-get install -y maven && \
    rm -rf /var/lib/apt/lists/*

# Work directory inside the container
WORKDIR /app

# Copy the co project into the image
COPY . .

# Build the project (creates target/co-1.0-SNAPSHOT.jar)
RUN mvn clean package -DskipTests

# Run the application
CMD ["java", \
  "-Djavax.net.ssl.trustStore=/app/truststore.p12", \
  "-Djavax.net.ssl.trustStorePassword=password", \
  "-Djavax.net.ssl.trustStoreType=PKCS12", \
  "-jar", \
  "/app/target/co-1.0-SNAPSHOT.jar" \
]
