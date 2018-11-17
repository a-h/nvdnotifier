package logger

import (
	"github.com/sirupsen/logrus"
)

// For creates a logger.
func For(pkg, fn string) *logrus.Entry {
	return logrus.WithField("pkg", pkg).WithField("fn", fn)
}

func init() {
	logrus.SetFormatter(&logrus.JSONFormatter{})
}
