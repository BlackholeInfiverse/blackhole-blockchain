#!/bin/bash

# BlackHole Blockchain Data Rollback Script
# Snapshot and restore ./data/ directories without modifying DB code

set -e

# Configuration
DATA_DIR="./data"
SNAPSHOT_DIR="./snapshots"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] INFO: $1${NC}"
}

log_success() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] SUCCESS: $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}"
}

log_error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}"
}

# Create snapshot directory if it doesn't exist
ensure_snapshot_dir() {
    if [ ! -d "$SNAPSHOT_DIR" ]; then
        mkdir -p "$SNAPSHOT_DIR"
        log_info "Created snapshot directory: $SNAPSHOT_DIR"
    fi
}

# Create a snapshot of the data directory
create_snapshot() {
    local snapshot_name="${TIMESTAMP}_data_snapshot.tar.gz"

    if [ ! -d "$DATA_DIR" ]; then
        log_warning "Data directory $DATA_DIR does not exist, nothing to snapshot"
        return 0
    fi

    log_info "Creating snapshot: $snapshot_name"

    # Create compressed tar archive
    if tar -czf "$SNAPSHOT_DIR/$snapshot_name" -C . "data" 2>/dev/null; then
        log_success "Snapshot created successfully: $SNAPSHOT_DIR/$snapshot_name"
        echo "$snapshot_name"
    else
        log_error "Failed to create snapshot"
        return 1
    fi
}

# List available snapshots
list_snapshots() {
    log_info "Available snapshots in $SNAPSHOT_DIR:"

    if [ ! -d "$SNAPSHOT_DIR" ]; then
        log_warning "Snapshot directory does not exist"
        return 0
    fi

    local count=0
    for snapshot in "$SNAPSHOT_DIR"/*.tar.gz; do
        if [ -f "$snapshot" ]; then
            local size=$(du -h "$snapshot" | cut -f1)
            local mtime=$(stat -c %y "$snapshot" 2>/dev/null || stat -f %Sm -t "%Y-%m-%d %H:%M:%S" "$snapshot")
            echo "  $(basename "$snapshot") (${size}, ${mtime})"
            ((count++))
        fi
    done

    if [ $count -eq 0 ]; then
        log_info "No snapshots found"
    fi
}

# Restore from a snapshot
restore_snapshot() {
    local snapshot_name="$1"

    if [ -z "$snapshot_name" ]; then
        log_error "Snapshot name is required"
        echo "Usage: $0 restore <snapshot_name>"
        list_snapshots
        return 1
    fi

    local snapshot_path="$SNAPSHOT_DIR/$snapshot_name"

    if [ ! -f "$snapshot_path" ]; then
        log_error "Snapshot not found: $snapshot_path"
        list_snapshots
        return 1
    fi

    log_warning "This will overwrite the current data directory. Are you sure? (y/N)"
    read -r confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        log_info "Restore cancelled"
        return 0
    fi

    log_info "Restoring from snapshot: $snapshot_name"

    # Backup current data before restore (safety measure)
    if [ -d "$DATA_DIR" ]; then
        local backup_name="pre_restore_${TIMESTAMP}.tar.gz"
        log_info "Creating safety backup: $backup_name"
        tar -czf "$SNAPSHOT_DIR/$backup_name" -C . "data" 2>/dev/null || true
    fi

    # Remove current data directory
    if [ -d "$DATA_DIR" ]; then
        rm -rf "$DATA_DIR"
    fi

    # Extract snapshot
    if tar -xzf "$snapshot_path" -C . 2>/dev/null; then
        log_success "Snapshot restored successfully from: $snapshot_name"
    else
        log_error "Failed to restore snapshot"
        return 1
    fi
}

# Clean old snapshots
clean_snapshots() {
    local days=${1:-30}

    if [ ! -d "$SNAPSHOT_DIR" ]; then
        log_warning "Snapshot directory does not exist"
        return 0
    fi

    log_info "Cleaning snapshots older than $days days"

    local count=0
    find "$SNAPSHOT_DIR" -name "*.tar.gz" -mtime +$days -delete -print | while read -r file; do
        log_info "Removed old snapshot: $(basename "$file")"
        ((count++))
    done

    if [ $count -eq 0 ]; then
        log_info "No old snapshots to clean"
    else
        log_success "Cleaned $count old snapshots"
    fi
}

# Show usage
usage() {
    echo "BlackHole Blockchain Data Rollback Script"
    echo "Usage: $0 <command> [options]"
    echo ""
    echo "Commands:"
    echo "  snapshot          Create a new snapshot of ./data/"
    echo "  restore <name>    Restore from a specific snapshot"
    echo "  list              List all available snapshots"
    echo "  clean [days]      Clean snapshots older than N days (default: 30)"
    echo ""
    echo "Examples:"
    echo "  $0 snapshot"
    echo "  $0 restore 20231201_120000_data_snapshot.tar.gz"
    echo "  $0 list"
    echo "  $0 clean 7"
}

# Main function
main() {
    ensure_snapshot_dir

    case "${1:-}" in
        snapshot)
            create_snapshot
            ;;
        restore)
            restore_snapshot "$2"
            ;;
        list)
            list_snapshots
            ;;
        clean)
            clean_snapshots "$2"
            ;;
        *)
            usage
            exit 1
            ;;
    esac
}

# Run main function
main "$@"