package com.sendoracloud.sdk.internal

import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.InetAddress
import java.net.ServerSocket
import kotlin.concurrent.thread

/**
 * A minimal HTTP/1.1 responder on a raw socket bound to 127.0.0.1 — the real
 * `HttpURLConnection` path, headers and all. (The unit-test compile classpath
 * is android.jar, which has no `com.sun.net.httpserver`.) Reads the request
 * head + Content-Length body, answers the scripted status / headers / body,
 * closes the connection. One scripted answer applies to every path.
 */
internal class TestHttpResponder : AutoCloseable {
    @Volatile var status = 200
    @Volatile var headers: Map<String, String> = emptyMap()
    @Volatile var body: String? = """{"success":true,"data":{}}"""
    @Volatile var hits = 0
    val paths: MutableList<String> = java.util.Collections.synchronizedList(mutableListOf())

    private val server = ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"))
    val baseUrl: String get() = "http://127.0.0.1:${server.localPort}"

    init {
        thread(isDaemon = true) {
            while (!server.isClosed) {
                val socket = runCatching { server.accept() }.getOrNull() ?: break
                socket.use { s ->
                    val reader = BufferedReader(InputStreamReader(s.getInputStream(), Charsets.ISO_8859_1))
                    var length = 0
                    val requestLine = reader.readLine() ?: return@use
                    paths += requestLine.split(" ").getOrElse(1) { "" }
                    while (true) {
                        val line = reader.readLine() ?: break
                        if (line.isEmpty()) break
                        if (line.lowercase().startsWith("content-length:")) length = line.substringAfter(":").trim().toInt()
                    }
                    repeat(length) { reader.read() }
                    hits++
                    val bytes = body?.toByteArray() ?: ByteArray(0)
                    val head = StringBuilder("HTTP/1.1 $status X\r\n")
                    headers.forEach { (k, v) -> head.append("$k: $v\r\n") }
                    head.append("Content-Type: application/json\r\nContent-Length: ${bytes.size}\r\nConnection: close\r\n\r\n")
                    s.getOutputStream().apply { write(head.toString().toByteArray(Charsets.ISO_8859_1)); write(bytes); flush() }
                }
            }
        }
    }

    fun answer(code: Int, json: String?, vararg h: Pair<String, String>) {
        status = code; body = json; headers = h.toMap()
    }

    override fun close() = server.close()
}
