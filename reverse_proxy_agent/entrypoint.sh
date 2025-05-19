#!/bin/sh

poetry run reverse-proxy-agent init &&
poetry run reverse-proxy-agent serve