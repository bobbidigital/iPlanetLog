__author__ = 'Jeffery.Smith'

import re
import time
import StringIO
import copy
import logging
import datetime

class Error(Exception):
    def __init__(self,value):
        Exception.__init__(self)
        self._value = value

    def __str__(self):
        return self.value

class LogFormatError(Error):
    pass

class FieldDelimiterError(Error):
    pass

class iPlanetLogField(object):

    def __init__(self,field_name,starting_character=None,ending_character=None):
        non_delimited_fields ={ '-' : ("",field_name," "),
                                " " : ("","Empty", " "),
                                "%" : ("", field_name," ")
                              }
        try:
            values = non_delimited_fields[starting_character]
        except KeyError:
            values = (starting_character,field_name,ending_character)

        self.start_delimiter = values[0]
        self.name = values[1]
        self.end_delimiter = values[2]
        self.value = ""


    @property
    def regex_string(self):
        #The format line claims that the content-type field is space delimited, but when the charset variable is
        #present, there is a space. So we just make a special check for this. Sucks, I know.
        if re.match(".+(content-type)", self.name):
            pattern = r'%s((?:.+?(?:;\scharset=[^%s]+)?)|-)%s'    % (self.escape(self.start_delimiter),
                                                              self.escape(self.end_delimiter),
                                                              self.end_delimiter)
        elif self.start_delimiter:
            pattern=r'%s(.*?)%s\s' % (self.escape(self.start_delimiter),
                                       self.end_delimiter)

        elif self.isempty():
            pattern=r'(\s)'
        else:
            pattern = r'%s([^%s]+)%s' % (self.escape(self.start_delimiter),
                                        self.escape(self.end_delimiter),
                                        self.end_delimiter)
        return pattern

    def length(self):
        if self.isempty():
            spacing_offset = 1
        else:
            spacing_offset = len(self.value) + 1
        if self.start_delimiter:
            spacing_offset += 2
        return spacing_offset


    def escape(self,string):
        ESCAPE_DELIMITERS = ("[", "]", "(",")")
        if string in ESCAPE_DELIMITERS:
            string = "\%s" % string
        return string

    def isempty(self):
        return self.name == 'Empty'


class iPlanetLogRecord(object):
    #Implemented an internal dictionary for field objects. This is for the as_string function which will perform
    #faster than making repeated calls to getattr

    def __init__(self,fields=None,errors=None,private_to_public_names=None):
        self._field_name_dict = {}
        self.field_map = private_to_public_names
        try:
            for field in fields:
                if not field.name == self.value_not_present() and not field.isempty():
                    public_field_name = private_to_public_names[field.name]
                    setattr(self,public_field_name,field.value)
                    self._field_name_dict[public_field_name] = field.value
            self._separate_combined_fields()
            self.error = False
            self.error_msg = ""
        except TypeError:
            logging.error("%s Parsing Error: %s" % (str(datetime.datetime.now()), fields))
            self.error = True
            self.error_msg = fields


    def as_string(self,delimiter=" ",replace_spaces=False, ordered_output=None):
        string_output = []
        fields = ordered_output or self._get_property_names()
        for attribute in fields:
            if attribute.startswith('_'):
                continue
            value = self._field_name_dict[attribute]
            if replace_spaces:
                value = value.replace(" ","+")            
            string_output.append("%s%s" % (value,delimiter))
        return "%s" % ''.join(string_output)

    def as_dict(self,replace_spaces=False):
        fields = self._get_property_names()
        return_dict = {}
        for attribute in fields:
            if attribute.startswith('_'):
                continue
            value = getattr(self,attribute)
            if replace_spaces:
                value.replace(" ", "+")
            return_dict[attribute] = value
        return return_dict

    def value_not_present(self):
        return "-"

    def _get_property_names(self):
        fields = self._field_name_dict.values()
        for field in ('date','time','request','version','url','query_string'):
            fields.append(field)
        return fields

    def _format_date_time(self):
        new_date = ''
        month_abbreviations = {'Jan': '01', 'Feb': '02', 'Mar': '03', 'Apr': '04',
                               'May': '05', 'Jun': '06', 'Jul': '07', 'Aug': '08',
                               'Sep': '09', 'Oct': '10', 'Nov': '11', 'Dec': '12'}
        year = self._datetime[7:11]
        month = self._datetime[3:6]
        day = self._datetime[0:2]
        new_date = "%s/%s/%s" % (month_abbreviations[month], day, year)
        setattr(self,'date',new_date)
        self._field_name_dict['date'] = new_date

        try:
            value = re.match('.+([0-9]{2}:[0-9]{2}:[0-9]{2}).+',self._datetime).group(1)
            self._field_name_dict['time'] = value
        except AttributeError:
            value = self.value_not_present()
        self._field_name_dict['time'] = value
        setattr(self,'time',self._field_name_dict['time'])


    def _separate_combined_fields(self):
        self._format_date_time()
        value = ''
        property_patterns = { 'request' : r'([A-Za-z]+).+', 'url' : '[A-Za-z]+\s([^\s|?]+)',
                              'query_string' : '.+\?([^\s]+)','version' : '(HTTP[^\s]+)' }

        for property, regex in property_patterns.iteritems():
            try:
                value = re.match(regex,self._request_string).group(1)

            except AttributeError:
                value = self.value_not_present()
            finally:
                self._field_name_dict[property] = value
                setattr(self,property,value)

    @property
    def has_errors(self):
        return self.error


class iPlanetLogFile(object):

    def __init__(self,file):
        self._file = file
        self._fields = []
        self._field_names = {}
        self.chunk_size = 500
        line = self._file.readline()
        if "format=" in line:
            line = line.replace("format=", "")
        else:
            raise TypeError("Log file does not have the proper header")
        self._build_fields(line)
        self.first_success = 0
        self.rehash_success = 0


    def __iter__(self):
        return self

    def is_last_field(self,field):
        return field.name == self._fields[-1].name and not field.isempty()

    @property
    def fields(self):
        fields_copy = copy.deepcopy(self._fields)
        return fields_copy

    @property
    def paired_delimiters(self):
        return { "(" : ")", "[" : "]", "<" : ">", "{" : "}"}

    def read(self):
        data = self._file.next()
        return data

    def next(self):
        line = self.read()
        try:
            return self._parse_log_line(line)
        except FieldDelimiterError:
            return self.parse_by_field(line)

    def _parse_log_line(self,line):
        results = self.regex_object.match(line)
        populated_fields = []
        x = 1
        if results:
            for field in self.fields:
                field.value = results.group(x)
                populated_fields.append(field)
                x += 1
            self.first_success += 1
            return iPlanetLogRecord(fields=populated_fields, private_to_public_names=self._field_names)
        else:
            raise FieldDelimiterError('Could not parse with single regex')

    def parse_by_field(self,line):
        #This will go field by field in an attempt to parse the log. Sometimes we find the log entry does not match the
        #field delimiter specified. (Like url strings not being encoded prior to being sent to the log, so occasionally
        #an actual space character will show up, breaking the specified field format)
        line = StringIO.StringIO(line)
        offset = 0
        populated_fields = []
        for field in self.fields:
            try:
                field = self._extract_field(field,line,offset)
            except FieldDelimiterError as ex:
                try:
                    previous_field = populated_fields[-1]
                    previous_field_length = previous_field.length()
                    repaired_fields = self.reprocess_previous_field(previous_field,field,line)
                    populated_fields[-1] = repaired_fields['previous_field']
                    field = repaired_fields['current_field']
                    offset += (repaired_fields['previous_field'].length() - previous_field_length)
                except FieldDelimiterError, IndexError:
                    line.seek(0)
                    return iPlanetLogRecord( errors=line.readline(), private_to_public_names=self._field_names )
            populated_fields.append(field)
            offset += field.length()
        self.rehash_success += 1
        return iPlanetLogRecord(fields=populated_fields, private_to_public_names=self._field_names)

    def reprocess_previous_field(self,previous_field,current_field,line):
        line.seek(0)
        pattern = r'(.+?%s)' % re.escape(previous_field.value)
        data = line.readline()
        try:
            offset = len(re.match(pattern,data ).group(1) ) + 1
        except AttributeError:
            raise FieldDelimiterError(data)

        if offset > len(data):
            raise LogFormatError(data)
        dangling_field = copy.copy(previous_field)
        dangling_field = self._extract_field(dangling_field,line,offset)
        previous_field.value = ("%s%s%s") % (previous_field.value, previous_field.end_delimiter,
                                             dangling_field.value)
        offset += dangling_field.length()
        try:
            field = self._extract_field(current_field,line,offset)
            current_field = field
        except FieldDelimiterError as ex:
            field = self.reprocess_previous_field(previous_field,current_field,line)

        return { 'previous_field' :previous_field, 'current_field' :current_field }


    def _extract_field(self,field,line, offset=0,chunk_size=None):
        line.seek(0)
        chunk_size = chunk_size or self.chunk_size
        line.seek(offset)
        data = line.read(chunk_size)
        try:
            field.value = re.match(field.regex_string,data).group(1)
        except AttributeError:
           # if data == '':
           #     raise FieldDelimiterError('Matching Record Not found')

            if field.isempty():
                field.value = ''
            else:
                if re.findall("\n", data):
                    if self.is_last_field(field):
                        field.value = data.rstrip()
                    else:
                        raise FieldDelimiterError("Line doesn't match format:\n %s" % re.match(r'(.+\n)', data).group(0))
                else:
                    chunk_size += chunk_size
                    field = self._extract_field(field,line,offset=offset,chunk_size=chunk_size)
        return field

    def _build_fields(self,line):
        start = ""
        end = ""
        field = []
        line = StringIO.StringIO(line)
        character = line.read(1)
        while not len(character) == 0:
            if not start:
                start = character
                if start in ("-", " "):
                    field.append(character)
                    end = character
                elif start in self.paired_delimiters:
                    end = self.paired_delimiters[start]
                    character = line.read(1)
                    continue
                else:
                    end = start
                    character = line.read(1)
                    continue
            if character == end:
                self._fields.append(iPlanetLogField(''.join(field), starting_character=start, ending_character=end))
                #Skip the space delimiter
                x = line.read(1)
                #Sometimes an extra space or two shows up in the header. The space is also
                #replicated in the file format. If this current character is a space
                #we shouldn't assume that the next read is going to be a character.
                if character.isspace():
                    character = x
                else:
                    character = line.read(1)
                field = []
                start = ""
                end = ""
            else:
                field.append(character)
                character = line.read(1)
        self._build_regex_string()
        self._build_field_lookup()

    def field_to_attribute(self,field_name):
        return self._field_names[field_name]


    def _build_field_lookup(self):
        expressions = {'clientip' : '.+client\.ip', 'user' : '.+auth-user', 'content_length' : '.+content-length',
                       'referer' : '.+referer', 'cookies' : '.+cookie', 'user_agent' : '.+user-agent',
                       '_datetime' : '.+SYSDATE', '_request_string' : '.+clf-request',
                       'status' : '.+clf-status', 'content_type' : '.+content-type' }
        for field in self._fields:
            for attribute, pattern in expressions.iteritems():
                if re.match(pattern, field.name):
                    self._field_names[field.name] = attribute
                    break

    def _build_regex_string(self):
        regex_string_list = []
        for field in self._fields:
            regex_string_list.append("%s" % field.regex_string)
        regex_string = r''.join(regex_string_list)
        self.regex_string = r'^(?:%s)' % regex_string
        self.regex_object = re.compile(self.regex_string)

def main():
    start = time.time()
    file = "C:\\temp\\data\\access\\access.201111170000"
    file = open(file,'r')
    parser = iPlanetLogFile(file)
    output_file = open('C:\\temp\\data\\access\\converted_output.txt', 'w')
    error_count = 0
    output_order = ('clientip','user','date','request','status','user_agent','time','url',
        'query_string','cookies', 'referer')

    output_file.write("#Software: Microsoft Internet Information Services 6.0\n")
    output_file.write("#Version: 1.0\n")
    output_file.write("#Fields: c-ip cs-username date cs-method sc-status cs(User-Agent) time cs-uri-stem cs-uri-query cs(Cookie) cs(Referer)\n")
    write_buffer = []
    for entry in parser:
        if not entry.has_errors:
            pass
            write_buffer.append("%s\n" % entry.as_string(replace_spaces=True,ordered_output=output_order))
            if len(write_buffer) > 100:
                output_file.writelines(write_buffer)
                write_buffer = []
        else:
            print "Error loading\n %s" % entry.error_msg
            error_count += 1
    if write_buffer:
        output_file.writelines(write_buffer)
    print "Number of Errors %s" % error_count
    print "First pass success: %s" % parser.first_success
    print "Rehash success: %s" % parser.rehash_success
    print "Elapsed time: %d" % (time.time() - start)
    output_file.close()
if __name__ == "__main__":
    main()



