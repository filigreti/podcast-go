# Use the official Go image as the base image
FROM golang:latest

# Set the working directory inside the container
WORKDIR /app

# Copy only the necessary files for Go module dependencies
COPY go.mod go.sum ./

# Download and cache Go modules
RUN go mod download

# Copy the entire project into the container
COPY . .

# Build the Go application
RUN go build -o /app/myapp ./cmd

# Command to run the executable
CMD ["/app/myapp"]
