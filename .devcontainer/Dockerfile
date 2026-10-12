FROM mcr.microsoft.com/devcontainers/python:1-3.11-bookworm
# The base image ships a Yarn apt source whose signing key has rotated;
# ExtProbe does not use Yarn, so remove it to keep apt-get working.
RUN rm -f /etc/apt/sources.list.d/yarn.list
