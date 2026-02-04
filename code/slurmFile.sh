#!/bin/bash
#SBATCH -J packetProcess              # Job name
#SBATCH -c 4                          # Request 4 CPU cores
#SBATCH -t 2:00:00                    # Max runtime of 2 hours
#SBATCH -o packetProcess-%j.out      # Stdout and stderr output
#SBATCH -e packetProcess-%j.out
#SBATCH -G 1                          # Request 1 GPU
#SBATCH --mail-type=ALL              # Email notifications
#SBATCH --mail-user=rd980@scarletmail.rutgers.edu
export PYTHONPATH=$HOME/.local/lib/python3.10.12/site-packages:$PYTHONPATH

# Set up CUDA environment
export CUDA_HOME=/usr/local/cuda
export PATH=$CUDA_HOME/bin:$PATH
export LD_LIBRARY_PATH=$CUDA_HOME/lib64:$LD_LIBRARY_PATH

echo "Running on host: $(hostname)"
echo "Job started at: $(date)"
echo "CUDA Path: $CUDA_HOME"
which nvcc
nvcc --version

# Compile CUDA code
echo "Compiling packetProcess.cu..."
nvcc -o packetProcess packetProcess.cu -lpcap

# Run with power monitoring
echo "Running packetProcess with power logging..."
python3 run_with_power_logging.py