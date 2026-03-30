#!/bin/bash

if [[ -z "$1" ]]; then
	echo "❌ Error: No version number provided."
	echo "Usage: $0 <version>"
	exit 1
fi

VERSION="$1"
OUTPUT_DIR="release_zips/$VERSION"
ADDON_DIR="demo/addons/godot-mariadb-connector"
ADDON_ZIP="$OUTPUT_DIR/addon.zip"
DEMO_ZIP="$OUTPUT_DIR/demo.zip"

if [[ ! -d "$ADDON_DIR" ]]; then
	echo "❌ Error: Addon directory '$ADDON_DIR' does not exist."
	exit 1
fi

if [[ ! -d "demo" ]]; then
	echo "❌ Error: Demo directory 'demo' does not exist."
	exit 1
fi

mkdir -p "$OUTPUT_DIR"

if [[ -f "$ADDON_ZIP" || -f "$DEMO_ZIP" ]]; then
	echo "❌ Error: ZIP(s) already exist in '$OUTPUT_DIR'. Remove them first if you want to rebuild."
	exit 1
fi

echo "📦 Creating addon.zip for Godot Asset Library..."
zip -r "$ADDON_ZIP" "$ADDON_DIR"

echo "📦 Creating demo.zip without addon folder..."
zip -r "$DEMO_ZIP" "demo" -x "$ADDON_DIR/*"

echo "🎉 Release files created in '$OUTPUT_DIR':"
echo "   - addon.zip"
echo "   - demo.zip"