#!/bin/bash
# BlackHole Blockchain Docker Management Script

set -e

echo "🚀 BlackHole Blockchain Docker Manager"
echo "======================================"

case "$1" in
    "build")
        echo "🔨 Building Docker images..."
        docker-compose build --no-cache
        echo "✅ Build completed!"
        ;;
    
    "start")
        echo "🚀 Starting BlackHole Blockchain stack..."
        docker-compose up -d
        echo "✅ Stack started! Access:"
        echo "   🌐 Blockchain Dashboard: http://localhost:8080"
        echo "   🌉 Bridge Dashboard: http://localhost:8084"
        ;;
    
    "stop")
        echo "🛑 Stopping BlackHole Blockchain stack..."
        docker-compose down
        echo "✅ Stack stopped!"
        ;;
    
    "restart")
        echo "🔄 Restarting BlackHole Blockchain stack..."
        docker-compose down
        docker-compose up -d
        echo "✅ Stack restarted!"
        ;;
    
    "logs")
        if [ -z "$2" ]; then
            echo "📋 Showing all logs..."
            docker-compose logs -f
        else
            echo "📋 Showing logs for $2..."
            docker-compose logs -f "$2"
        fi
        ;;
    
    "status")
        echo "📊 BlackHole Blockchain Stack Status:"
        docker-compose ps
        ;;
    
    "clean")
        echo "🧹 Cleaning up Docker resources..."
        docker-compose down -v
        docker system prune -f
        echo "✅ Cleanup completed!"
        ;;
    
    "test")
        echo "🧪 Testing Docker setup..."
        echo "📝 Building images..."
        docker-compose build
        echo "🚀 Starting services..."
        docker-compose up -d
        sleep 10
        echo "🔍 Checking health..."
        curl -f http://localhost:8080/health || echo "❌ Blockchain health check failed"
        curl -f http://localhost:8084/health || echo "❌ Bridge health check failed"
        echo "✅ Test completed!"
        ;;
    
    *)
        echo "Usage: $0 {build|start|stop|restart|logs|status|clean|test}"
        echo ""
        echo "Commands:"
        echo "  build    - Build Docker images"
        echo "  start    - Start the blockchain stack"
        echo "  stop     - Stop the blockchain stack"
        echo "  restart  - Restart the blockchain stack"
        echo "  logs     - Show logs (optionally specify service: blockchain|bridge)"
        echo "  status   - Show stack status"
        echo "  clean    - Clean up Docker resources"
        echo "  test     - Test the complete setup"
        exit 1
        ;;
esac