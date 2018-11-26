#pragma once

#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>

#define LOG_VERSION "0.1.0"

#define SHORT_FILE(file)	(strrchr(file, '\\') + 1)
typedef void( *log_LockFn )( void *udata, int lock );

enum { LOG_TRACE, LOG_DEBUG, LOG_INFO, LOG_WARN, LOG_ERROR, LOG_FATAL };

#define log_trace(...) log_log(LOG_TRACE, SHORT_FILE(__FILE__), __LINE__, __VA_ARGS__)
#define log_debug(...) log_log(LOG_DEBUG, SHORT_FILE(__FILE__), __LINE__, __VA_ARGS__)
#define log_info(...)  log_log(LOG_INFO,  SHORT_FILE(__FILE__), __LINE__, __VA_ARGS__)
#define log_warn(...)  log_log(LOG_WARN,  SHORT_FILE(__FILE__), __LINE__, __VA_ARGS__)
#define log_error(...) log_log(LOG_ERROR, SHORT_FILE(__FILE__), __LINE__, __VA_ARGS__)
#define log_fatal(...) log_log(LOG_FATAL, SHORT_FILE(__FILE__), __LINE__, __VA_ARGS__)

void log_set_udata( void *udata );
void log_set_lock( log_LockFn fn );
void log_set_fp( FILE *fp );
void log_set_level( int level );
void log_set_quiet( int enable );

void log_log( int level, const char *file, int line, const char *fmt, ... );

static struct {
	void *udata;
	log_LockFn lock;
	FILE *fp;
	int level;
	int quiet;
} L;


static const char *level_names[] = {
	"TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL"
};

#ifdef LOG_USE_COLOR
static const char *level_colors[] = {
	"\x1b[94m", "\x1b[36m", "\x1b[32m", "\x1b[33m", "\x1b[31m", "\x1b[35m"
};
#endif


inline static void lock( void ) {
	if ( L.lock ) {
		L.lock( L.udata, 1 );
	}
}


inline static void unlock( void ) {
	if ( L.lock ) {
		L.lock( L.udata, 0 );
	}
}


inline void log_set_udata( void *udata ) {
	L.udata = udata;
}


inline void log_set_lock( log_LockFn fn ) {
	L.lock = fn;
}


inline void log_set_fp( FILE *fp ) {
	L.fp = fp;
}


inline void log_set_level( int level ) {
	L.level = level;
}


inline void log_set_quiet( int enable ) {
	L.quiet = enable ? 1 : 0;
}


inline void log_log( int level, const char *file, int line, const char *fmt, ... ) {
	if ( level < L.level ) {
		return;
	}

	/* Acquire lock */
	lock();

	/* Get current time */
	time_t t = time( NULL );
	struct tm lt;
	localtime_s( &lt, &t );

	/* Log to stderr */
	if ( !L.quiet ) {
		va_list args;
		char buf[16];
		buf[strftime( buf, sizeof( buf ), "%H:%M:%S", &lt )] = '\0';
#ifdef LOG_USE_COLOR
		fprintf(
			stderr, "%s %s%-5s\x1b[0m \x1b[90m%s:%d:\x1b[0m ",
			buf, level_colors[level], level_names[level], file, line );
#else
		fprintf( stderr, "%s %-5s %s:%d: ", buf, level_names[level], file, line );
#endif
		va_start( args, fmt );
		vfprintf( stderr, fmt, args );
		va_end( args );
		fprintf( stderr, "\n" );
	}

	/* Log to file */
	if ( L.fp ) {
		va_list args;
		char buf[32];
		buf[strftime( buf, sizeof( buf ), "%Y-%m-%d %H:%M:%S", &lt )] = '\0';
		fprintf( L.fp, "%s %-5s %s:%d: ", buf, level_names[level], file, line );
		va_start( args, fmt );
		vfprintf( L.fp, fmt, args );
		va_end( args );
		fprintf( L.fp, "\n" );
	}

	/* Release lock */
	unlock();
}