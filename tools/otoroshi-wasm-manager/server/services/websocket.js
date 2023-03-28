const { Server } = require("socket.io");

let io;

const createLogsWebSocket = server => {
  io = new Server(server);
}

const emit = (channel, release, message) => {
  io.emit(channel, `[${release ? "RELEASE" : "BUILD"}] ${message}`)
}

const emitError = (channel, release, message) => {
  io.emit(channel, `ERROR - [${release ? "RELEASE" : "BUILD"}] ${message}`)
}

module.exports = {
  WebSocket: {
    createLogsWebSocket,
    emit,
    emitError,
  }
}