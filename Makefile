CC		= gcc
LIB_SOURCES = file.c converter.c
APP_SOURCES = main.c $(LIB_SOURCES)
APP_OBJECTS = $(APP_SOURCES:.c=.o)
LIB_OBJECTS = $(LIB_SOURCES:.c=.o)
APP 		= sigtopcap
APPLIB 		= libSigtopcap
INCLUDES 	= -I./include/
CFLAGS 		= -Wall -g -fPIC $(INCLUDES)
CFLAGS_STATIC = -Wall -g $(INCLUDES)

$(APP): $(APP_OBJECTS) 
	$(CC) $(CFLAGS) $^ -o $@ -ldl

dynlib: $(LIB_OBJECTS)
	$(CC) -shared -fPIC $^ -o $(APPLIB).so
	
staticlib: 
	$(CC) $(CFLAGS_STATIC) -c $(LIB_SOURCES)
	ar -cvq $(APPLIB).a -o $(LIB_OBJECTS)
	
obj: $(OBJECTS)

all:
	make clean
	make dynlib
	make staticlib
	make $(APP)
	mv $(APP) ./bin
	mv $(APPLIB).a ./bin
	mv $(APPLIB).so ./bin

install:
	cp ./bin/$(APP) /usr/bin/
	chmod 755 /usr/bin/$(APP)
clean:
	rm -f ./bin/$(APP) ./bin/$(APPLIB).so ./bin/$(APPLIB).a *.o *~