# Optional: Custom fluent-bit image with additional plugins
# Most users can use the official fluent/fluent-bit image directly

FROM fluent/fluent-bit:latest

# Copy custom configuration
COPY fluent-bit.conf /fluent-bit/etc/fluent-bit.conf
COPY parsers.conf /fluent-bit/etc/parsers.conf

# Expose syslog port if needed
EXPOSE 514/udp
