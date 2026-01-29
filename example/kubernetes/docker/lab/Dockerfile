ARG DOCKER_USERNAME=georgeleveln
ARG BASE_IMAGE=lab_base
ARG BASE_IMAGE_TAG=latest

FROM ${DOCKER_USERNAME}/${BASE_IMAGE}:${BASE_IMAGE_TAG}

# Set environment variables
ENV PROJECT_HOME=/opt/epics
ENV DEBIAN_FRONTEND=noninteractive

# Create user with pre-set password ("secret")
RUN useradd -m -s /bin/bash operator -g operator && echo "operator:secret" | chpasswd
RUN useradd -m -s /bin/bash guest                && echo "guest:secret"    | chpasswd

# Copy user-specific environment settings
COPY operator_bashrc /home/operator/.operator_bashrc
COPY guest_bashrc /home/guest/.guest_bashrc

RUN chown operator:operator /home/operator/.operator_bashrc && \
    chown guest:guest       /home/guest/.guest_bashrc       && \
    chmod 644               /home/operator/.operator_bashrc && \
    chmod 644               /home/guest/.guest_bashrc

RUN echo "source ~/.operator_bashrc" >> /home/operator/.bashrc
RUN echo "source ~/.guest_bashrc"    >> /home/guest/.bashrc

USER guest

CMD ["/bin/bash"]
