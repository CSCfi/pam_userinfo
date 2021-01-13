CXXFLAGS=-Wall -fPIC -std=c++11

LDLIBS=-lpam -lcurl

objects = src/pam_userinfo.o \
		  src/include/config.o

all: pam_userinfo.so

%.o: %.c %.h
	$(CXX) $(CXXFLAGS) -c $< -o $@

pam_userinfo.so: $(objects)
	$(CXX) -shared $^ $(LDLIBS) -o $@

clean:
	rm -f $(objects) pam_userinfo.so 
