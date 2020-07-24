package querylogger

import (
	"github.com/sirupsen/logrus"
)

var qlog = logrus.WithField("Package", "querylogger")
