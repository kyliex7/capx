#!/bin/bash

TARGET_IP="192.168.8.1"
TARGET_PORT=9090

echo "--- Starting Traffic Test ---"

echo "[1/3] Sending ICMP Echo Requests..."
ping -c 3 $TARGET_IP > /dev/null

echo "[2/3] Sending UDP Packets to port $TARGET_PORT..."
echo "test message" | nc -u -w1 $TARGET_IP $TARGET_PORT

echo "[3/3] Attempting TCP Connection to port $TARGET_PORT..."
nc -zv -w1 $TARGET_IP $TARGET_PORT

echo "--- Test Complete ---"
