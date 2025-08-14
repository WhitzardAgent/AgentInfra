docker build -t my-desktop .
docker run -it --rm -p 6080:6080 -p 9000:9000 --name my-desktop-container my-desktop
