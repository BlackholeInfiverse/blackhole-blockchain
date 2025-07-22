@echo off
echo 🌌 Blackhole Blockchain - Simple Fake Transaction Generator
echo ==========================================================
echo.
echo This is a simplified version that only requires MongoDB.
echo It generates fake transactions without full blockchain dependencies.
echo.
echo Starting simple fake transaction generator...
echo This will generate 3-5 transactions per second between:
echo   - Shivam:  03d0f85fe18231c5aa28cb3b405652a9f3ee1e9ef08aad36ad4c850c52f7bed10f
echo   - Shivam2: 02dc2e3faa525d9a343742e625a1e192560100288635d803a8883e22f7b65eef59
echo.
echo Make sure MongoDB is running on localhost:27017
echo Press Ctrl+C to stop the generator
echo.
pause
echo.

go run simple_fake_generator.go
