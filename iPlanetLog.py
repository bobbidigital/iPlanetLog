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
        non_delimited_fields ={ '-' : ("","-"," "),
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
            #pattern = r'%s([^%s]+(?:\scharset=[^%s]+)?)' % (self.escape(self.start_delimiter),
            pattern = r'%s(((?:[^%s]*(?:\scharset=[^%s]+)?|(-))))' % (self.escape(self.start_delimiter),
                                                      		      self.escape(self.end_delimiter),
                                                     		      self.end_delimiter)
        elif self.start_delimiter:
            pattern=r'%s(.*?)%s\s' % (self.escape(self.start_delimiter),
                                        self.end_delimiter)

        else:
            pattern = r'%s([^%s]*?)%s' % (self.escape(self.start_delimiter),
                                        self.escape(self.end_delimiter),
                                        self.end_delimiter)
        return pattern

    def length(self):
        spacing_offset = len(self.value) + 1

        if self.isempty():
            spacing_offset += 1
        if self.start_delimiter:
            spacing_offset += 2
        return spacing_offset


    def escape(self,string):
        ESCAPE_DELIMITERS = ("[", "]", "(",")")
        if string in ESCAPE_DELIMITERS:
            return "\%s" % string
        else:
            return string

    def isempty(self):
        return self.name == 'Empty'


class iPlanetLogRecord(object):
    def __init__(self,fields,errors=False):
        if errors:
            logging.error("%s Parsing Error: %s" % (str(datetime.datetime.now()), fields))
            self.error = True
            self.error_msg = fields
            for attribute in self._fields_processed().keys():
                setattr(self,attribute, "-")
        else:
            for field in fields:
                for attribute, pattern in self._fields_processed().iteritems():
                    if re.match(pattern, field.name):
                        setattr(self,attribute,field.value)
                        break
            self.error = False
            self.error_msg = ""



    def _fields_processed(self):
	#The intended attribute name as key, value is the regular expression to match it.
        expressions = {'clientip' : '.+client\.ip', 'user' : '.+auth-user', 'content_length' : '.+content-length',
                       'referer' : '.+referer', 'cookies' : '.+cookie', 'user_agent' : '.+user-agent',
                       '_datetime' : '.+SYSDATE', '_request_string' : '.+clf-request',
                       'status' : '.+clf-status', 'content_type' : '.+content-type' }
        return expressions


    def as_string(self,delimiter=" ",replace_spaces=False, ordered_output=None):
        string_output = []
        fields = ordered_output or self._get_properties()
        for attribute in fields:
            if attribute.startswith('_'):
                continue
            value = getattr(self,attribute)    
            if replace_spaces:
                value = value.replace(" ","+")            
            string_output.append(value)
            string_output.append(delimiter)
        return "%s" % ''.join(string_output)

    def as_dict(self,replace_spaces=False):
        fields = self._get_properties()
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

    def _get_properties(self):
        fields = self._fields_processed().keys()
        for field in ('date','time','request','version','url','query_string'):
            fields.append(field)
        return fields



    @property
    def has_errors(self):
        return self.error

    @property
    def date(self):
        try:
            value = re.match("([0-9]{2})/([A-Za-z]{3})/([0-9]{4})", self._datetime)
            date_string = "%s %s %s" % (value.group(1), value.group(2), value.group(3))
            time_struct = time.strptime(date_string, "%d %b %Y")
            return "%s/%s/%s" % (time_struct.tm_mon, time_struct.tm_mday, time_struct.tm_year)
        except AttributeError:
            return self.value_not_present()

    @property
    def time(self):
        try:
            return re.match('.+([0-9]{2}:[0-9]{2}:[0-9]{2}).+',self._datetime).group(1)
        except AttributeError:
            return self.value_not_present()

    @property
    def request(self):
        try:
            return re.match("([A-Za-z]+).+", self._request_string).group(1)
        except AttributeError:
            return self.value_not_present()

    @property
    def url(self):
        try:
            return re.match("[A-Za-z]+\s([^\s|?]+)", self._request_string).group(1)
        except AttributeError:
            return self.value_not_present()

    @property
    def query_string(self):
        try:
            value = re.match(".+\?([^\s]+)", self._request_string).group(1)
        except AttributeError:
            value = self.value_not_present()
        
        return value
        
    @property
    def version(self):
        try:
            return re.match(".+(HTTP[^\s]+)", self._request_string).group(1)
        except AttributeError:
            return self.value_not_present()

class iPlanetLogFile(object):

    def __init__(self,file):
        self._file = file
        self._fields = []
        self.chunk_size = 500
        line = self._file.readline()
        if "format=" in line:
            line = line.replace("format=", "")
        else:
            raise TypeError("Log file does not have the proper header")
        self._build_fields(line)


    def __iter__(self):
        return self


    def is_last_field(self,field):
        return field.name == self._fields[-1].name and not field.isempty()

    @property
    def paired_delimiters(self):
        return { "(" : ")", "[" : "]", "<" : ">", "{" : "}"}

    def read(self):
        return StringIO.StringIO(self._file.readline())

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


    def next(self):
        line = self.read()
        offset = 0
        populated_fields = []
        for field in self._fields:
            try:
                field = self._extract_field(field,line,offset)
            except FieldDelimiterError as ex:
                #I found a number of fields that have their defined delimiter in the string itself. Assuming the break
                #was from this. Try parsing the field again and see if that gets us back on track
                if populated_fields:
                    try:
                        previous_field = populated_fields[-1]
                        previous_field_length = previous_field.length()
                        repaired_fields = self.reprocess_previous_field(previous_field,field,line)
                        populated_fields[-1] = repaired_fields['previous_field']
                        field = repaired_fields['current_field']
                        offset += (repaired_fields['previous_field'].length() - previous_field_length)
                    except FieldDelimiterError:
                        line.seek(0)
                        return iPlanetLogRecord( line.readline(), errors=True )
            populated_fields.append(field)
            offset += field.length()
        return iPlanetLogRecord(populated_fields)

    def _extract_field(self,field,line, offset=0,chunk_size=None):
        line.seek(0)
        chunk_size = chunk_size or self.chunk_size
        line.seek(offset)
        data = line.read(chunk_size)

        try:
            field.value = re.match(field.regex_string,data).group(1)
        except AttributeError:
            if data == '':
                raise StopIteration

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

def main():

    file = "C:\\temp\\data\\log2_old.txt"
    parser = iPlanetLogFile(file)
    output_file = open('C:\\temp\\data\\converted_log2.txt', 'w')
    error_count = 0
    output_order = ('clientip','user','date','request','status','user_agent','time','url',
        'query_string','cookies', 'referer')

    output_file.write("#Software: Microsoft Internet Information Services 6.0\n")
    output_file.write("#Version: 1.0\n")
    output_file.write("#Fields: c-ip cs-username date cs-method sc-status cs(User-Agent) time cs-uri-stem cs-uri-query cs(Cookie) cs(Referer)\n")
    for entry in parser:
        if not entry.has_errors:
            output_file.write(entry.as_string(replace_spaces=True, ordered_output=output_order))
            output_file.write("\n")
        else:
            print "Error loading\n %s" % entry.error_msg
            error_count += 1

    print "Number of Errors %s" % error_count
    output_file.close()
if __name__ == "__main__":
    main()



