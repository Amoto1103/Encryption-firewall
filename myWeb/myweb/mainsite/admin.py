# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.contrib import admin
from .models import Rule
from .models import IP
# Register your models here.
class ID(admin.ModelAdmin):
	list_display=('name','id')

admin.site.register(Rule,ID)
admin.site.register(IP)
