# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models

# Create your models here.
class Rule(models.Model):
	PRO_CHOICE=(('0','NONE'),('1','ICMP'),('6','TCP'),('17','UDP'),)
	name=models.CharField(max_length=100)
	protocol=models.CharField(max_length=2,choices=PRO_CHOICE)
	sourceIP=models.GenericIPAddressField()
	sourcePort=models.PositiveIntegerField()
	desIP=models.GenericIPAddressField()
	desPort=models.PositiveIntegerField()

	def __unicode__(self):
		return self.name

class IP(models.Model):
	IPaddress=models.GenericIPAddressField()
	
	def __unicode__(self):
		return self.IPaddress

