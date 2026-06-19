exports.handler = async (event) => {
  return {
    statusCode: 200,
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      message: "Hello from a REAL Yantra-deployed Lambda backend",
      method: event.requestContext?.http?.method || "GET",
      path: event.rawPath || "/",
      time: new Date().toISOString(),
    }),
  };
};
