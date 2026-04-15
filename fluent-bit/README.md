# fluent-bit Configuration for Shrike

This directory contains the fluent-bit configuration for ingesting logs and forwarding them to Shrike's HTTP API.

## Overview

fluent-bit serves as the log ingestion layer, replacing the embedded OTel Collector. It:

1. **Tails Docker container logs** from `/var/lib/docker/containers/`
2. **Optionally tails syslog** from `/var/log/syslog`
3. **Parses logs** using JSON (Docker) and RFC5424 (syslog) parsers
4. **Forwards to Shrike** via HTTP POST to `/v1/ingest`

## Files

- `fluent-bit.conf` - Main fluent-bit configuration
- `parsers.conf` - Custom parser definitions (Docker JSON, syslog)
- `Dockerfile` - Optional custom fluent-bit image (not required)

## Usage

### With docker-compose

```bash
cd /path/to/shrike
docker compose up -d
```

This starts both `shrike` and `fluent-bit` containers. fluent-bit will:
- Wait for shrike to be healthy
- Start tailing logs
- Forward to shrike's HTTP API

### Standalone

```bash
docker run -d \
  --name fluent-bit \
  -v /var/lib/docker/containers:/var/lib/docker/containers:ro \
  -v /var/log:/var/log:ro \
  -v $(pwd)/fluent-bit:/fluent-bit/etc:ro \
  fluent/fluent-bit:latest
```

## Configuration

### Input Sources

| Source | Path | Parser | Tag |
|--------|------|--------|-----|
| Docker containers | `/var/lib/docker/containers/*/*.log` | docker_json | docker.* |
| System syslog | `/var/log/syslog` | syslog_rfc5424 | syslog |

### Output

- **Destination**: Shrike HTTP API
- **Endpoint**: `http://shrike:8080/v1/ingest`
- **Format**: JSON
- **Retry**: Disabled (let WAL handle durability)

### Log Rotation

fluent-bit uses a SQLite database (`/var/log/fluent-bit/positions.db`) to track file positions. This ensures:
- No data loss during log rotation
- Resume from last position after restart
- Handles concurrent log writes

## Troubleshooting

### Check fluent-bit logs

```bash
docker compose logs fluent-bit
```

### Verify log flow

```bash
# Check if fluent-bit is running
docker compose ps fluent-bit

# Check for errors
docker compose logs fluent-bit | grep -i error

# Verify logs are being sent
docker compose logs shrike | grep "ingest"
```

### Common Issues

**"No such file or directory" for /var/log/syslog**
- Syslog may not exist on all systems
- Comment out the syslog INPUT section if not needed

**"Permission denied" for Docker containers**
- fluent-bit needs read access to `/var/lib/docker/containers/`
- Ensure the fluent-bit container has appropriate permissions

**Logs not appearing in Shrike**
- Check Shrike health: `curl http://localhost:8080/health`
- Check fluent-bit output: `docker compose logs fluent-bit | grep -i "sent"`
- Test direct ingestion: `curl -X POST http://localhost:8080/v1/ingest -H "Content-Type: application/json" -d '{"logs": ["test"]}'`

## Customization

### Add new log sources

Edit `fluent-bit.conf` and add a new INPUT section:

```ini
[INPUT]
    Name          tail
    Path          /path/to/your/log.log
    Parser        your_parser
    Tag           your_tag
    db            /var/log/fluent-bit/positions.db
```

### Add custom parsers

Edit `parsers.conf` and add a new PARSER section:

```ini
[PARSER]
    Name        your_parser
    Format      regex
    Regex       ^(?P<field1>\S+)\s+(?P<field2>\S+)$
    Time_Key    timestamp
    Time_Format %Y-%m-%d %H:%M:%S
```

### Change output destination

Edit the OUTPUT section in `fluent-bit.conf`:

```ini
[OUTPUT]
    Name          http
    Match         *
    Host          your-shrike-host
    Port          8080
    URI           /v1/ingest
```

## Performance

- **Memory limit**: 5MB per input (adjust `Mem_Buf_Limit`)
- **Flush interval**: 5 seconds
- **Retry limit**: Disabled (infinite retries handled by WAL)

## Security

- All volumes are mounted read-only (`:ro`)
- No network access beyond Shrike HTTP API
- No authentication required (Shrike handles auth if configured)
